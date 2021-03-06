# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class AliasPathAttributes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The attributes of the token that the alias path is referring to.
    """

    NONE = "None"  #: The token that the alias path is referring to has no attributes.
    MODIFIABLE = "Modifiable"  #: The token that the alias path is referring to is modifiable by policies with 'modify' effect.

class AliasPathTokenType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the token that the alias path is referring to.
    """

    NOT_SPECIFIED = "NotSpecified"  #: The token type is not specified.
    ANY = "Any"  #: The token type can be anything.
    STRING = "String"  #: The token type is string.
    OBJECT = "Object"  #: The token type is object.
    ARRAY = "Array"  #: The token type is array.
    INTEGER = "Integer"  #: The token type is integer.
    NUMBER = "Number"  #: The token type is number.
    BOOLEAN = "Boolean"  #: The token type is boolean.

class AliasPatternType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of alias pattern
    """

    NOT_SPECIFIED = "NotSpecified"  #: NotSpecified is not allowed.
    EXTRACT = "Extract"  #: Extract is the only allowed value.

class AliasType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the alias.
    """

    NOT_SPECIFIED = "NotSpecified"  #: Alias type is unknown (same as not providing alias type).
    PLAIN_TEXT = "PlainText"  #: Alias value is not secret.
    MASK = "Mask"  #: Alias value is secret.

class CreatedByType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of identity that created the resource.
    """

    USER = "User"
    APPLICATION = "Application"
    MANAGED_IDENTITY = "ManagedIdentity"
    KEY = "Key"

class EnforcementMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The policy assignment enforcement mode. Possible values are Default and DoNotEnforce.
    """

    DEFAULT = "Default"  #: The policy effect is enforced during resource creation or update.
    DO_NOT_ENFORCE = "DoNotEnforce"  #: The policy effect is not enforced during resource creation or update.

class ExemptionCategory(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The policy exemption category. Possible values are Waiver and Mitigated.
    """

    WAIVER = "Waiver"  #: This category of exemptions usually means the scope is not applicable for the policy.
    MITIGATED = "Mitigated"  #: This category of exemptions usually means the mitigation actions have been applied to the scope.

class ParameterType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The data type of the parameter.
    """

    STRING = "String"
    ARRAY = "Array"
    OBJECT = "Object"
    BOOLEAN = "Boolean"
    INTEGER = "Integer"
    FLOAT = "Float"
    DATE_TIME = "DateTime"

class PolicyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of policy definition. Possible values are NotSpecified, BuiltIn, Custom, and Static.
    """

    NOT_SPECIFIED = "NotSpecified"
    BUILT_IN = "BuiltIn"
    CUSTOM = "Custom"
    STATIC = "Static"

class ResourceIdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The identity type. This is the only required field when adding a system assigned identity to a
    resource.
    """

    SYSTEM_ASSIGNED = "SystemAssigned"  #: Indicates that a system assigned identity is associated with the resource.
    NONE = "None"  #: Indicates that no identity is associated with the resource or that the existing identity should be removed.
