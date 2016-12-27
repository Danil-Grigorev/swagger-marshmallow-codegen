import re
from marshmallow.validate import(
    Length,
    Regexp
)
class X(Schema):
    team = fields.String(validate=[Regexp(regex=re.compile('team[1-9][0-9]+'))])
    team2 = fields.String(validate=[Length(min=None, max=10, equal=None), Regexp(regex=re.compile('team[1-9][0-9]+'))])
