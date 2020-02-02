"""Application Categories Class."""

from fmcapi.api_objects.apiclasstemplate import APIClassTemplate
import logging
import warnings


class ApplicationCategories(APIClassTemplate):
    """The ApplicationCategories Object in the FMC."""

    VALID_JSON_DATA = ["id", "name", "type"]
    VALID_FOR_KWARGS = VALID_JSON_DATA + []
    URL_SUFFIX = "/object/applicationcategories"
    VALID_CHARACTERS_FOR_NAME = """[.\w\d_\- ]"""

    def __init__(self, fmc, **kwargs):
        """
        Initialize ApplicationCategories object.

        :param fmc: (object) FMC object
        :param kwargs: Any other values passed during instantiation.
        :return: None
        """
        super().__init__(fmc, **kwargs)
        logging.debug("In __init__() for ApplicationCategories class.")
        self.parse_kwargs(**kwargs)

    def post(self):
        """POST method for API for ApplicationCategories not supported."""
        logging.info("POST method for API for ApplicationCategories not supported.")
        pass

    def put(self):
        """PUT method for API for ApplicationCategories not supported."""
        logging.info("PUT method for API for ApplicationCategories not supported.")
        pass

    def delete(self):
        """PUT method for API for ApplicationCategories not supported."""
        logging.info("DELETE method for API for ApplicationCategories not supported.")
        pass


class ApplicationCategory(ApplicationCategories):
    """
    Dispose of this Class after 20210101.

    Use ApplicationCategories() instead.
    """

    def __init__(self, fmc, **kwargs):
        warnings.resetwarnings()
        warnings.warn(
            "Deprecated: ApplicationCategory() should be called via ApplicationCategories()."
        )
        super().__init__(fmc, **kwargs)
