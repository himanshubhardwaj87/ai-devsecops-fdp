FROM python:latest
ADD https://example.com/bootstrap.sh /tmp/bootstrap.sh
WORKDIR /srv
COPY . /srv
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]
