import datetime

from tornado import web

import boto

from IPython.html.services.notebooks.nbmanager import NotebookManager
from IPython.nbformat import current
from IPython.utils.traitlets import Unicode

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
            name = self.bucket.get_key(self.s3_prefix + notebook_id).get_metadata('nbname')
            self.mapping[notebook_id] = name

    def list_notebooks(self):
        data = [dict(notebook_id=id, name=name) for id, name in self.mapping.items()]
        data = sorted(data, key=lambda item: item['name'])
        return data

    def _read_notebook(self, notebook_id):
        if not self.notebook_exists(notebook_id):
            raise web.HTTPError(404, u'Notebook does not exist: %s' % notebook_id)
        try:
            key = self.bucket.get_key(self.s3_prefix + notebook_id)
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
        return self.s3_prefix + notebook_id + '/checkpoints/' + checkpoint_id

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
        print "list_checkpoints %s" % (self.s3_prefix + notebook_id + '/checkpoints/')
        keys = self.bucket.list(self.s3_prefix + notebook_id + '/checkpoints/')

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
