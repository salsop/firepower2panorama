"""URL Categories Class."""

from fmcapi.api_objects.apiclasstemplate import APIClassTemplate
import logging
import warnings


class URLCategories(APIClassTemplate):
    """The URLCategories Object in the FMC."""

    VALID_JSON_DATA = ["id", "name", "type"]
    VALID_FOR_KWARGS = VALID_JSON_DATA + []
    URL_SUFFIX = "/object/urlcategories"
    VALID_CHARACTERS_FOR_NAME = """[.\w\d_\-\/\.\(\) ]"""

    def __init__(self, fmc, **kwargs):
        """
        Initialize URLCategories object.

        :param fmc: (object) FMC object
        :param kwargs: Any other values passed during instantiation.
        :return: None
        """
        super().__init__(fmc, **kwargs)
        logging.debug("In __init__() for URLCategories class.")
        self.parse_kwargs(**kwargs)

    def post(self):
        """POST method for API for URLCategories not supported."""
        logging.info("POST method for API for URLCategories not supported.")
        pass

    def put(self):
        """PUT method for API for URLCategories not supported."""
        logging.info("PUT method for API for URLCategories not supported.")
        pass

    def delete(self):
        """DELETE method for API for URLCategories not supported."""
        logging.info("DELETE method for API for URLCategories not supported.")
        pass


class URLCategory(URLCategories):
    """
    Dispose of this Class after 20210101.

    Use URLCategories() instead.
    """

    def __init__(self, fmc, **kwargs):
        warnings.resetwarnings()
        warnings.warn("Deprecated: URLCategory() should be called via URLCategories().")
        super().__init__(fmc, **kwargs)
