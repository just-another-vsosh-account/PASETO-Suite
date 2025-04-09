# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, render_template
from lib import PasetoToken
import re
import secrets

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        
        # Проверяем наличие всех необходимых полей
        required_fields = ['key', 'token', 'purpose']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Конвертируем hex-строку ключа в bytes
        try:
            key = bytes.fromhex(data['key'])
        except ValueError:
            return jsonify({"error": "Invalid key format"}), 400

        # Создаем токен с использованием ключа
        try:
            token = PasetoToken.from_paseto(key, data['token'])
            payload = token.decrypt()
            return jsonify({"payload": payload})
        except Exception as e:
            return jsonify({"error": f"Decryption error: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        
        # Проверяем наличие всех необходимых полей
        required_fields = ['key', 'payload', 'version', 'purpose']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        # Если ключ пустой, генерируем новый
        if not data['key']:
            # Генерируем 32 байта (256 бит) и конвертируем в hex
            key = secrets.token_hex(32)
        else:
            key = data['key'].lower()
            # Проверяем формат ключа только если он предоставлен
            if not re.match(r'^[0-9a-f]{64}$', key):
                return jsonify({"error": "Invalid key format"}), 400

        # Создаем токен с использованием ключа
        token = PasetoToken(
            key=bytes.fromhex(key),
            version=data['version'],
            purpose=data['purpose'],
            payload=data['payload'],
            footer=data.get('footer', '')
        )
        encoded = token.encrypt()
        if isinstance(encoded, bytes):
            encoded = encoded.decode('utf-8')

        # Возвращаем результат
        response = {
            'token': encoded,
            'key': key  # Возвращаем ключ только если он был сгенерирован
        }
        
        return jsonify(response)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500
    
@app.route('/aggreement', methods=['GET'])
def aggreement():
    return render_template('AGREEMENT')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
