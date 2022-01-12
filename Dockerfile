FROM python:3.7-slim
COPY . /

RUN python setup.py sdist bdist_wheel
RUN tar -xzf dist/*.tar.gz
RUN pip install -e swagger-marshmallow-codegen*

CMD swagger-marshmallow-codegen

