# -*- coding:utf-8 -*-
from myschema import (
    MySchema,
    ObjectId
)
from marshmallow import fields
import bson


class Person(MySchema):
    id = ObjectId(missing=lambda: bson.ObjectId('5872bad4c54d2d4e78b34c9d'))
    name = fields.String(required=True)
    age = fields.Integer()