import datetime
import os

from tornado import web
import logging

import boto
import json
from IPython.html.services.notebooks.nbmanager import NotebookManager
from IPython.html.services.notebooks.filenbmanager import sort_key

from IPython.nbformat import current
from IPython.utils.traitlets import Unicode, TraitError


class S3NotebookManager2(NotebookManager):

    aws_access_key_id = Unicode(config=True, help='AWS access key id.')
    aws_secret_access_key = Unicode(config=True, help='AWS secret access key.')
    s3_bucket = Unicode('', config=True, help='Bucket name for notebooks.')
    s3_prefix = Unicode('', config=True, help='Key prefix of notebook location')
    save_script = Unicode('', config=True, help='Save script config')
    notebook_dir = s3_bucket
    checkpoint_dir = Unicode('.ipynb_checkpoints', config=True,
                             help="""The directory name in which to keep notebook checkpoints
                             This is a path relative to the notebook's own directory.
                             By default, it is .ipynb_checkpoints""")

    def __init__(self, **kwargs):
        super(S3NotebookManager2, self).__init__(**kwargs)
        # Configuration of aws access keys default to '' since it's unicode.
        # boto will fail if empty strings are passed therefore convert to None
        access_key = self.aws_access_key_id if self.aws_access_key_id else None
        secret_key = self.aws_secret_access_key if self.aws_secret_access_key else None
        self.s3_con = boto.connect_s3(access_key, secret_key)
        self.bucket = self.s3_con.get_bucket(self.s3_bucket)

    def _copy(self, src, dest):
        k = self.bucket.lookup(src)
        try:
            k.copy(self.s3_bucket, dest, preserve_acl=True)
            return True
        except OSError as e:
            self.log.debug("copystat on %s failed", dest, exc_info=True)
            return False

    def _move(self, src, dest):
        success = self._copy(src, dest)
        if success:
            self.bucket.delete_key(src)
        return False

    def _notebook_dir_changed(self, name, old, new):
        """Do a bit of validation of the notebook dir."""
        if not os.path.isabs(new):
            # If we receive a non-absolute path, make it absolute.
            self.notebook_dir = new
            return
        if not self.path_exists(new):
            raise TraitError("notebook dir %r is not a directory" % new)

    def _get_s3_path(self, name=None, path=''):
        if name is None:
            path = path + '/'
        else:
            if not path:
                path = name
            else:
                path = path + '/' + name
        return path

    def path_exists(self, path, name=None):
        s3_path = self._get_s3_path(path=path, name=name)
        print 'path exists', s3_path
        key = self.bucket.get_key(s3_path)
        if not key:
            return False
        return key

    def list_dirs(self, path):
        path = path.strip('/')
        if not self.path_exists(path=path):
            raise web.HTTPError(404, u'directory does not exist: %r' % path)

        keys = self.bucket.list(path, '/')
        dirs = []
        for key in keys:
            # prefix is a folder
            print 'dir:', key.name, path + '/'
            if isinstance(key, boto.s3.prefix.Prefix):
                # and (key.name != (path + '/'))
                model = self.get_dir_model(key, path)
                if (not self.is_hidden(model)) and (self.checkpoint_dir not in model['path']):
                    #and (path != path)
                    dirs.append(model)
        dirs.sort(key=sort_key)
        return dirs

    def get_dir_model(self, key, path=''):
        #import pdb;pdb.set_trace()
        model = {}
        model['name'] = key.name.replace(path + '/', '')
        model['path'] = path
        model['last_modified'] = ''
        model['created'] = ''
        model['type'] = 'directory'
        return model

    def notebook_exists(self, name, path=''):
        print 'notebook exists:', path, name
        return self.path_exists(name=name, path=path)

    def get_notebook_names(self, path=''):
        names = []
        newpath = path[1:] if path.startswith('/') else path

        k = self.path_exists(path=newpath)
        if not k:
            raise web.HTTPError(404, 'Directory not found: ' + newpath)

        #keys = [x for x in self.bucket.list(path.strip('/') + '/', '/')]

        pp = '/' if not path else path
        keys = [x for x in self.bucket.list(newpath, pp)]
        print 'notebooks list:', path, keys
        for key in keys:
            print '/' + key.name, path, ('/'+key.name).startswith(path + '/')
            #import pdb;pdb.set_trace()
            if ((key.name.endswith('.ipynb') == True) and
                ('/' + key.name).startswith(path + '/') and
                (self.checkpoint_dir not in key.name)):
                print 'filter notebok:', key.name, path
                names.append(key.name)
        return names

    def list_notebooks(self, path):
        #import pdb;pdb.set_trace()
        print 'list:', path
        notebook_names = self.get_notebook_names(path)
        notebooks = [self.get_notebook(('/'+name).replace(path + '/', ''),
                                       path + '/',
                                       content=False)
                     for name in notebook_names if self.should_list(name)]
        notebooks.sort(key=sort_key)
        return notebooks

    def get_notebook(self, name, path='', content=True):
        if not self.notebook_exists(name=name, path=path):
            raise web.HTTPError(404, u'Notebook does not exist: %s' % name)

        model = {}
        model['name'] = ('/' + name).replace((path + '/'), '').strip('/')
        model['path'] = path
        model['last_modified'] = datetime.datetime.now()
        model['created'] = datetime.datetime.now()
        if content:
            try:
                key = self.bucket.get_key(self._get_s3_path(name, path))
                model['type'] = 'notebook'
                nb = json.loads(key.get_contents_as_string())
                self.mark_trusted_cells(nb, name, path)
                model['content'] = nb
            except Exception as e:
                logging.exception(e)
                raise web.HTTPError(400, u"Unreadable Notebook: %s %s" % (path, e))
        return model

    def save_notebook(self, model, name='', path=''):
        path = path[1:] if path.startswith('/') else path

        if 'content' not in model:
            raise web.HTTPError(400, u'No notebook JSON data provided')

        # One checkpoint should always exist

        if self.notebook_exists(name, path) and not self.list_checkpoints(name, path):
            self.create_checkpoint(name, path)

        new_path = model.get('path', path)
        new_name = model.get('name', name)

        if path != new_path or name != new_name:
            self.rename_notebook(name, path, new_name, new_path)

        s3_path = self._get_s3_path(new_name, new_path)
        nb = current.to_notebook_json(model['content'])

        if 'name' in nb['metadata']:
            nb['metadata']['name'] = u''
        try:
            self.log.debug("Autosaving notebook %s", s3_path)
            key = self.bucket.new_key(s3_path)
            key.set_metadata('nbname', new_name)
            key.set_contents_from_string(json.dumps(nb))
        except Exception as e:
            raise web.HTTPError(400, u'Unexpected error while autosaving notebook: %s %s' % (s3_path, e))

        if self.save_script:
            py_path = os.path.splitext(s3_path)[0] + '.py'
            self.log.debug("Writing script %s", py_path)
            try:
                key = self.bucket.new_key(py_path)
                key.set_metadata('nbname', new_name)
                key.set_contents_from_string(nb)
            except Exception as e:
                raise web.HTTPError(400, u'Unexpected error while saving notebook as script: %s %s' % (py_path, e))

        model = self.get_notebook(new_name, new_path, content=False)
        return model

    def get_checkpoint_path(self, checkpoint_id, name, path=''):
        """find the path to a checkpoint"""
        basename, _ = os.path.splitext(name)
        filename = u"{name}-{checkpoint_id}{ext}".format(
            name=basename,
            checkpoint_id=checkpoint_id,
            ext=self.filename_ext,
        )

        s3_path = self._get_s3_path(path=path)
        cp_dir = os.path.join(s3_path, self.checkpoint_dir)
        if not self.path_exists(cp_dir):
            self.bucket.new_key(cp_dir + '/')
        cp_path = os.path.join(cp_dir, filename)
        return cp_path

    def get_checkpoint_model(self, checkpoint_id, name, path=''):
        """construct the info dict for a given checkpoint"""
        cp_path = self.get_checkpoint_path(checkpoint_id, name, path)
        info = {'id': checkpoint_id, 'last_modified': datetime.datetime.now()}
        return info

    def create_checkpoint(self, name, path=''):
        """Create a checkpoint from the current state of a notebook"""
        s3_path = self._get_s3_path(name, path)
        # only the one checkpoint ID:
        checkpoint_id = u"checkpoint"
        cp_path = self.get_checkpoint_path(checkpoint_id, name, path)
        self.log.debug("creating checkpoint for notebook %s", name)
        self._copy(s3_path, cp_path)
        # return the checkpoint info
        return self.get_checkpoint_model(checkpoint_id, name, path)

    def delete_checkpoint(self, checkpoint_id, name, path=''):
        path = path.strip('/')
        cp_path = self.get_checkpoint_path(checkpoint_id, name, path)
        if not self.path_exists(cp_path):
            raise web.HTTPError(404,
                u'Notebook checkpoint does not exist: %s%s-%s' % (path, name, checkpoint_id)
            )
        self.log.debug("unlinking %s", cp_path)
        self.bucket.delete_key(cp_path)

    def list_checkpoints(self, name, path=''):
        checkpoint_id = "checkpoint"
        print 'list_checkpoins'
        s3_path = self.get_checkpoint_path(checkpoint_id, name, path).strip('/')
        if not self.path_exists(path=None, name=s3_path):
            return []
        else:
            return [self.get_checkpoint_model(checkpoint_id, name, path)]

    def restore_checkpoint(self, checkpoint_id, name, path=''):
        self.log.info("restoring Notebook %s from checkpoint %s", name, checkpoint_id)
        nb_path = self._get_s3_path(name, path)
        cp_path = self.get_checkpoint_path(checkpoint_id, name, path)
        if not self.path_exists(cp_path):
            self.log.debug("checkpoint file does not exist: %s", cp_path)
            raise web.HTTPError(404,
                u'Notebook checkpoint does not exist: %s-%s' % (name, checkpoint_id)
            )
        # ensure notebook is readable (never restore from an unreadable notebook)
        key = self.bucket.get_key(cp_path)
        nb = key.get_contents_as_string()
        current.reads_json(nb)
        self._copy(cp_path, nb_path)
        self.log.debug("copying %s -> %s", cp_path, nb_path)

    def update_notebook(self, model, name, path=''):
        """Update the notebook's path and/or name"""
        new_name = model.get('name', name)
        new_path = model.get('path', path).strip('/')
        if path != new_path or name != new_name:
            self.rename_notebook(name, path, new_name, new_path)
        model = self.get_notebook(new_name, new_path, content=False)
        return model

    def delete_notebook(self, name, path=''):
        s3_path = self._get_s3_path(name, path)
        print s3_path
        if not self.notebook_exists(name, path):
            raise web.HTTPError(404, u'Notebook does not exist: %s' % s3_path)

        # clear checkpoints
        for checkpoint in self.list_checkpoints(name, path):
            checkpoint_id = checkpoint['id']
            cp_path = self.get_checkpoint_path(checkpoint_id, name, path).strip('/')
            print 'delete:', cp_path
            if self.path_exists(name=cp_path, path=None):
                self.log.debug("Unlinking checkpoint %s", cp_path)
                self.log.debug("Unlinking notebook checkoint %s", s3_path)
                self.bucket.delete_key(cp_path)

        self.log.debug("Unlinking notebook %s", s3_path)
        self.bucket.delete_key(s3_path)

    def rename_notebook(self, old_name, old_path, new_name, new_path):
        old_path = old_path.strip('/')
        new_path = new_path.strip('/')
        if new_name == old_name and new_path == old_path:
            return

        new_s3_path = self._get_s3_path(new_name, new_path).strip('/')
        old_s3_path = self._get_s3_path(old_name, old_path).strip('/')

        # Should we proceed with the move?
        if self.path_exists(new_s3_path):
            raise web.HTTPError(409, u'Notebook with name already exists: %s' % new_s3_path)
        if self.save_script:
            old_py_path = os.path.splitext(old_s3_path)[0] + '.py'
            new_py_path = os.path.splitext(new_s3_path)[0] + '.py'
            if self.path_exists(new_py_path):
                raise web.HTTPError(409, u'Python script with name already exists: %s' % new_py_path)

        # Move the notebook file
        try:
            self.log.debug("Renaming notebook %s -> %s", old_s3_path, new_s3_path)
            self._move(old_s3_path, new_s3_path)
        except Exception as e:
            raise web.HTTPError(500, u'Unknown error renaming notebook: %s %s' % (old_s3_path, e))

        # Move the checkpoints
        old_checkpoints = self.list_checkpoints(old_name, old_path)
        for cp in old_checkpoints:
            checkpoint_id = cp['id']
            old_cp_path = self.get_checkpoint_path(checkpoint_id, old_name, old_path).strip('/')
            new_cp_path = self.get_checkpoint_path(checkpoint_id, new_name, new_path).strip('/')
            if self.path_exists(name=old_cp_path, path=None):
                self.log.debug("Renaming checkpoint %s -> %s", old_cp_path, new_cp_path)
                self._move(old_cp_path, new_cp_path)

        # Move the .py script
        if self.save_script:
            self._move(old_py_path, new_py_path)

    def is_hidden(self, path):
        print 'is_hidden:', path
        if isinstance(path, dict):
            return path.get('name', '').startswith('.')
        return False

    def info_string(self):
        return "Serving notebooks from s3. bucket name: %s" % self.s3_bucket


class S3NotebookManager(NotebookManager):

    aws_access_key_id = Unicode(config=True, help='AWS access key id.')
    aws_secret_access_key = Unicode(config=True, help='AWS secret access key.')
    s3_bucket = Unicode('', config=True, help='Bucket name for notebooks.')
    s3_prefix = Unicode('', config=True, help='Key prefix of notebook location')

    def __init__(self, **kwargs):
        super(S3NotebookManager, self).__init__(**kwargs)
        # Configuration of aws access keys default to '' since it's unicode.
        # boto will fail if empty strings are passed therefore convert to None
        access_key = self.aws_access_key_id if self.aws_access_key_id else None
        secret_key = self.aws_secret_access_key if self.aws_secret_access_key else None
        self.s3_con = boto.connect_s3(access_key, secret_key)
        self.bucket = self.s3_con.get_bucket(self.s3_bucket)

    def load_notebook_names(self):
        self.mapping = {}
        keys = self.bucket.list(self.s3_prefix)

        for key in keys:
            tokens = key.name.split('/')
            if len(tokens) > 2 and tokens[-2] == 'checkpoints':
                continue
            notebook_id = tokens[-1]
            name = self.bucket.get_key(notebook_id).get_metadata('nbname')
            self.mapping[notebook_id] = name

    def list_notebooks(self):
        self.load_notebook_names()
        data = [dict(notebook_id=id, name=name) for id, name in self.mapping.items()]
        data = sorted(data, key=lambda item: item['name'])
        return data

    def _read_notebook(self, notebook_id):
        if not self.notebook_exists(notebook_id):
            raise web.HTTPError(404, u'Notebook does not exist: %s' % notebook_id)
        try:
            key = self.bucket.get_key(notebook_id)
            s = key.get_contents_as_string()
        except:
            raise web.HTTPError(500, u'Notebook cannot be read.')
        return s

    def _parse_notebook(self, s):
        try:
            # v1 and v2 and json in the .ipynb files.
            nb = current.reads(s, u'json')
        except:
            raise web.HTTPError(500, u'Unreadable JSON notebook.')
        return nb

    def read_notebook_object(self, notebook_id):
        s = self._read_notebook(notebook_id)

        nb = self._parse_notebook(s)

        # Todo: The last modified should actually be saved in the notebook document.
        # We are just using the current datetime until that is implemented.
        last_modified = datetime.datetime.utcnow()
        return last_modified, nb

    def write_notebook_object(self, nb, notebook_id=None):
        try:
            new_name = nb.metadata.name
        except AttributeError:
            raise web.HTTPError(400, u'Missing notebook name')

        if notebook_id is None:
            notebook_id = self.new_notebook_id(new_name)

        try:
            data = current.writes(nb, u'json')
        except Exception as e:
            raise web.HTTPError(400, u'Unexpected error while saving notebook: %s' % e)

        try:
            key = self.bucket.new_key(self.s3_prefix + notebook_id)
            key.set_metadata('nbname', new_name)
            key.set_contents_from_string(data)
        except Exception as e:
            raise web.HTTPError(400, u'Unexpected error while saving notebook: %s' % e)

        self.mapping[notebook_id] = new_name
        return notebook_id

    def info_string(self):
        return "Serving notebooks from s3. bucket name: %s" % self.s3_bucket

    # Checkpoint-related utilities
    def _get_checkpoint_path(self, notebook_id, checkpoint_id):
        """find the path to a checkpoint"""
        return notebook_id + '/checkpoints/' + checkpoint_id

    def _get_checkpoint_info(self, notebook_id, checkpoint_id):
        """construct the info dict for a given checkpoint"""
        #path = self._get_checkpoint_path(notebook_id, checkpoint_id)
        #key = self.bucket.get_key(path)
        # nbname = key.get_metadata('nbname')
        #last_modified = datetime.datetime.strptime(key.last_modified, '%a, %d %b %Y %H:%M:%S %Z')
        last_modified = datetime.datetime.strptime(checkpoint_id, '%Y-%m-%dT%H:%M:%SZ')
        info = dict(
            checkpoint_id=checkpoint_id,
            last_modified=last_modified,
        )

        return info

    # public checkpoint API

    def create_checkpoint(self, notebook_id):
        """Create a checkpoint from the current state of a notebook"""
        checkpoint_id = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        cp_path = self._get_checkpoint_path(notebook_id, checkpoint_id)
        self.log.debug("creating checkpoint for notebook %s", notebook_id)

        s = self._read_notebook(notebook_id)
        try:
            key = self.bucket.new_key(cp_path)
            key.set_contents_from_string(s)
        except Exception as e:
            raise web.HTTPError(400, u'Unexpected error while saving checkpoint: %s' % e)

        # return the checkpoint info
        return self._get_checkpoint_info(notebook_id, checkpoint_id)

    def list_checkpoints(self, notebook_id):
        """list the checkpoints for a given notebook
        """
        keys = self.bucket.list(notebook_id + '/checkpoints/')

        checkpoints = []
        for key in keys:
            checkpoint_id = key.name.split('/')[-1]
            # name = self.bucket.get_key(self.s3_prefix + id).get_metadata('nbname')
            last_modified = datetime.datetime.strptime(checkpoint_id, '%Y-%m-%dT%H:%M:%SZ')
            info = dict(
                checkpoint_id=checkpoint_id,
                last_modified=last_modified,
            )
            checkpoints.append(info)
        return checkpoints

    def restore_checkpoint(self, notebook_id, checkpoint_id):
        """restore a notebook to a checkpointed state"""
        self.log.info("restoring Notebook %s from checkpoint %s", notebook_id, checkpoint_id)
        cp_path = self._get_checkpoint_path(notebook_id, checkpoint_id)
        try:
            key = self.bucket.get_key(cp_path)
            data = key.get_contents_as_string()
        except:
            raise web.HTTPError(500, u'Notebook checkpoint cannot be read.')

        # ensure notebook is readable (never restore from an unreadable notebook)
        nb = self._parse_notebook(data)

        # Don't change the name just because we're restoring
        name = self.mapping[notebook_id]
        nb.metadata.name = name

        self.write_notebook_object(nb, notebook_id)

    def delete_checkpoint(self, notebook_id, checkpoint_id):
        """delete a notebook's checkpoint"""
        cp_path = self._get_checkpoint_path(notebook_id, checkpoint_id)
        self.bucket.delete_key(cp_path)

    def delete_notebook(self, notebook_id):
        bucketListResultSet = self.bucket.list(prefix=notebook_id)
        self.bucket.delete_keys([key.name for key in bucketListResultSet])
