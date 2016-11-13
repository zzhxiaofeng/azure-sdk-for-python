# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class PurchasePlan(Model):
    """Used for establishing the purchase context of any 3rd Party artifact
    through MarketPlace.

    :param publisher: The publisher ID.
    :type publisher: str
    :param name: The plan ID.
    :type name: str
    :param product: The product ID.
    :type product: str
    """ 

    _validation = {
        'publisher': {'required': True},
        'name': {'required': True},
        'product': {'required': True},
    }

    _attribute_map = {
        'publisher': {'key': 'publisher', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'product': {'key': 'product', 'type': 'str'},
    }

    def __init__(self, publisher, name, product):
        self.publisher = publisher
        self.name = name
        self.product = product
