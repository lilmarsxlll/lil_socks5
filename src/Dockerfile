FROM python:3.14-slim
WORKDIR /src
RUN pip install --upgrade pip wheel "poetry==2.2.1"
RUN poetry config virtualenvs.create false
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root
COPY . .
EXPOSE 1080
CMD ["python", "main.py"]