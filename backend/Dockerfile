FROM python:3.10-slim

# Supaya log Python langsung keluar ke stdout (tidak di-buffer),
# dan tidak ada file .pyc yang dibuat di dalam container.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Buat folder instance agar SQLite volume bisa di-mount dengan benar
RUN mkdir -p /app/instance

EXPOSE 5000

# Pakai python app.py (bukan flask run) agar startup logic di app.py
# berjalan dengan benar — termasuk DEV_BYPASS_AUTH check dan database.init_db().
CMD ["python", "app.py"]