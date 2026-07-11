FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Buat folder instance agar SQLite volume bisa di-mount dengan benar
RUN mkdir -p /app/instance

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]