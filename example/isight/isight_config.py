
class ISightConfig(object):
    """
    Configuration for iSight Connector.

    This class populates fields by reading a config file.
    """
    def __init__(self, config_filepath):

        self.keys = [
            "source_path",
            "iSightRemoteImportUsername",
            "iSightRemoteImportPassword",
            "iSightRemoteImportPublicKey",
            "iSightRemoteImportPrivateKey",
            "iSightRemoteImportUrl",
            "iSightRemoteImportDaysBack",
            "iSightLocalRawDataFilename",
        ]

        self.source_path = config_filepath

        # HARDCODED DEFAULTS
        self.iSightRemoteImportUsername = None
        self.iSightRemoteImportPassword = None
        self.iSightRemoteImportPublicKey = None
        self.iSightRemoteImportPrivateKey = None
        self.iSightRemoteImportUrl = "https://mysight-api.isightpartners.com/"
        self.iSightRemoteImportDaysBack=180
        self.iSightLocalRawDataFilename = None

        with open(config_filepath, "r") as cfg:
            lineno = 0
            for line in cfg:
                try:
                    lineno += 1

                    line = line.strip()
                    if not line or line[0] == "#":
                        continue

                    name, val = line.split("=", 1)

                    # TODO validate name is within spec
                    # -- this will require careful re-evalutaion of config params as we are
                    # now relying on properties being listed in .conf file even
                    # though some of those properties were never listed in this class

                    # if we are reading a new value for an existing attribute, lets make
                    # sure we preserve the type
                    try:
                        existing_attr = getattr(self, name)
                        if existing_attr is not None:
                            val = type(existing_attr)(val)
                    except AttributeError:
                        pass

                    setattr(self, name, val)

                except Exception as e:
                    pass

    def as_dict(self):
        """
        """
        res = {}
        for key in self.keys:
            res[key] = getattr(self, key)

        return res
