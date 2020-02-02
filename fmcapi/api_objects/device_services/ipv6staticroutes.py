"""IPv6 Static Routes Classes."""

from fmcapi.api_objects.apiclasstemplate import APIClassTemplate
from .devicerecords import DeviceRecords
from fmcapi.api_objects.object_services.networkaddresses import NetworkAddresses
from fmcapi.api_objects.object_services.hosts import Hosts
from fmcapi.api_objects.object_services.networkgroups import NetworkGroups
import logging
import warnings


class IPv6StaticRoutes(APIClassTemplate):
    """The IPv6StaticRoute Object in the FMC."""

    VALID_JSON_DATA = [
        "id",
        "name",
        "interfaceName",
        "selectedNetworks",
        "gateway",
        "routeTracking",
        "metricValue",
        "isTunneled",
    ]
    VALID_FOR_KWARGS = VALID_JSON_DATA + ["device_name"]
    PREFIX_URL = "/devices/devicerecords"
    URL_SUFFIX = None
    REQUIRED_FOR_POST = ["interfaceName", "selectedNetworks", "gateway"]
    REQUIRED_FOR_PUT = ["id", "device_id"]

    def __init__(self, fmc, **kwargs):
        """
        Initialize IPv6StaticRoutes object.

        Set self.type to "IP6StaticRoute" and parse the kwargs.

        :param fmc (object): FMC object
        :param **kwargs: Any other values passed during instantiation.
        :return: None
        """
        super().__init__(fmc, **kwargs)
        logging.debug("In __init__() for IPv6StaticRoute class.")
        self.type = "IPv6StaticRoute"
        self.parse_kwargs(**kwargs)

    def parse_kwargs(self, **kwargs):
        """
        Parse the kwargs and set self variables to match.

        :return: None
        """
        super().parse_kwargs(**kwargs)
        logging.debug("In parse_kwargs() for IPv6StaticRoute class.")
        if "device_name" in kwargs:
            self.device(device_name=kwargs["device_name"])

    def device(self, device_name):
        """
        Associate device to this route.

        :param device_name: (str) Name of device.
        :return: None
        """
        logging.debug("In device() for IPv6StaticRoute class.")
        device1 = DeviceRecords(fmc=self.fmc)
        device1.get(name=device_name)
        if "id" in device1.__dict__:
            self.device_id = device1.id
            self.URL = f"{self.fmc.configuration_url}{self.PREFIX_URL}/{self.device_id}/routing/ipv6staticroutes"
            self.device_added_to_url = True
        else:
            logging.warning(
                f"Device {device_name} not found.  Cannot set up device for IPv6StaticRoute."
            )

    def networks(self, action, networks):
        """
        Set of networks associated with this route.

        :param action: (str) 'add', 'remove', or 'clear'
        :param networks: (list)  List of IP Hosts, IP Networks, and/or Network Groups.
        :return: None
        """
        logging.info("In networks() for IPv6StaticRoute class.")
        if action == "add":
            # Valid objects are IPHost, IPNetwork and NetworkGroup.
            # Create a dictionary to contain all three object type.
            ipaddresses_json = NetworkAddresses(fmc=self.fmc).get()
            networkgroup_json = NetworkGroups(fmc=self.fmc).get()
            items = ipaddresses_json.get("items", []) + networkgroup_json.get(
                "items", []
            )
            for network in networks:
                # Find the matching object name in the dictionary if it exists
                net1 = list(filter(lambda i: i["name"] == network, items))
                if len(net1) > 0:
                    if "selectedNetworks" in self.__dict__:
                        # Check to see if network already exists
                        exists = list(
                            filter(
                                lambda i: i["id"] == net1[0]["id"],
                                self.selectedNetworks,
                            )
                        )
                        if "id" in exists:
                            logging.warning(
                                f'Network "{network}" already exists in selectedNetworks.'
                            )
                        else:
                            self.selectedNetworks.append(
                                {
                                    "type": net1[0]["type"],
                                    "id": net1[0]["id"],
                                    "name": net1[0]["name"],
                                }
                            )
                    else:
                        self.selectedNetworks = [
                            {
                                "type": net1[0]["type"],
                                "id": net1[0]["id"],
                                "name": net1[0]["name"],
                            }
                        ]
                else:
                    logging.warning(
                        f'Network "{network}" not found.  Cannot set up device for IPv6StaticRoute.'
                    )
        elif action == "remove":
            ipaddresses_json = NetworkAddresses(fmc=self.fmc).get()
            networkgroup_json = NetworkGroups(fmc=self.fmc).get()
            items = ipaddresses_json.get("items", []) + networkgroup_json.get(
                "items", []
            )
            for network in networks:
                net1 = list(filter(lambda i: i["name"] == network, items))
                if len(net1) > 0:
                    if "selectedNetworks" in self.__dict__:
                        self.selectedNetworks = list(
                            filter(
                                lambda i: i["id"] != net1[0]["id"],
                                self.selectedNetworks,
                            )
                        )
                    else:
                        logging.warning(
                            "No selectedNetworks found for this Device's IPv6StaticRoute."
                        )
                else:
                    logging.warning(
                        f'Network "{network}" not found.  Cannot set up device for IPv6StaticRoute.'
                    )
        elif action == "clear":
            if "selectedNetworks" in self.__dict__:
                del self.selectedNetworks
                logging.info(
                    "All selectedNetworks removed from this IPv6StaticRoute object."
                )

    def gw(self, name):
        """
        Gateway for this route.

        :param name: (str) Name of object that is the gateway address.
        :return: None
        """
        logging.info("In gw() for IPv6StaticRoute class.")
        gw1 = Hosts(fmc=self.fmc)
        gw1.get(name=name)
        if "id" in gw1.__dict__:
            self.gateway = {
                "object": {"type": gw1.type, "id": gw1.id, "name": gw1.name}
            }
        else:
            logging.warning(
                f'Network "{name}" not found.  Cannot set up device for IPv6StaticRoute.'
            )


class IPv6StaticRoute(IPv6StaticRoutes):
    """
    Dispose of this Class after 20210101.

    Use IPv6StaticRoutes() instead.
    """

    def __init__(self, fmc, **kwargs):
        warnings.resetwarnings()
        warnings.warn(
            "Deprecated: IPv6StaticRoute() should be called via IPv6StaticRoutes()."
        )
        super().__init__(fmc, **kwargs)
