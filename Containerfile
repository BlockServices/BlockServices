FROM python:3.14
WORKDIR /code
COPY requirements.txt .
RUN pip install --no-cache-dir -r ./requirements.txt
COPY . .
EXPOSE 8010
CMD ["uvicorn", "bsrv.main:app", "--host", "0.0.0.0", "--port", "8010"]
