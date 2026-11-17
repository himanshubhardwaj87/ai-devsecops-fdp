FROM public.ecr.aws/docker/library/python:3.13-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home shoplite
USER shoplite
EXPOSE 5000
HEALTHCHECK CMD python -c "import socket; socket.create_connection(('127.0.0.1', 5000), 2)"
CMD ["python", "app.py"]
