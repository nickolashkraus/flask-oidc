FROM python:3.11

RUN mkdir /src
WORKDIR /src
ADD . /src/
RUN pip install -r requirements.txt

EXPOSE 5000

# NOTE: `--host=0.0.0.0` makes the server publicly available on the network.
CMD ["flask", "--app", "src/app.py", "run", "--host=0.0.0.0"]
