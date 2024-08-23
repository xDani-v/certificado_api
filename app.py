import requests
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from PyPDF2 import PdfFileReader, PdfFileWriter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
import io
import os
import urllib.parse
import logging

app = Flask(__name__)
CORS(app)  # Habilitar CORS para todas las rutas

# Configurar el registro
logging.basicConfig(level=logging.DEBUG)

def download_p12(p12_url):
    response = requests.get(p12_url)
    response.raise_for_status()  # Asegurarse de que la descarga fue exitosa
    return response.content

def load_p12(p12_data, p12_password):
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        p12_data, p12_password.encode(), default_backend()
    )
    return private_key, certificate

def download_pdf(pdf_url):
    response = requests.get(pdf_url)
    response.raise_for_status()  # Asegurarse de que la descarga fue exitosa
    return response.content

def sign_pdf(pdf_data, private_key, output_path):
    # Leer el PDF
    pdf_reader = PdfFileReader(io.BytesIO(pdf_data))
    pdf_writer = PdfFileWriter()
    
    for page_num in range(pdf_reader.getNumPages()):
        pdf_writer.addPage(pdf_reader.getPage(page_num))
    
    # Crear una firma digital
    data_to_sign = b"Data to be signed"  # Aquí puedes usar el contenido del PDF o un hash del mismo
    signature = private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        SHA256()
    )
    
    # Adjuntar la firma al PDF (esto es un ejemplo simplificado)
    pdf_writer.addMetadata({
        '/Signature': signature.hex()
    })
    
    # Guardar el PDF firmado en un archivo
    with open(output_path, 'wb') as output_pdf_file:
        pdf_writer.write(output_pdf_file)

@app.route('/sign_pdf', methods=['POST'])
def sign_pdf_route():
    try:
        p12_url = request.form.get('P12_URL')
        p12_password = request.form.get('P12_PASSWORD')
        pdf_url = request.form.get('pdf_url')
        
        logging.debug(f'Received P12_URL: {p12_url}')
        logging.debug(f'Received P12_PASSWORD: {p12_password}')
        logging.debug(f'Received pdf_url: {pdf_url}')
        
        if not p12_url or not p12_password or not pdf_url:
            return jsonify({"error": "Missing one or more required parameters"}), 400
        
        # Descargar y cargar la clave privada y el certificado
        p12_data = download_p12(p12_url)
        private_key, certificate = load_p12(p12_data, p12_password)
        
        # Descargar el PDF desde la URL proporcionada
        pdf_data = download_pdf(pdf_url)
        
        # Obtener el nombre del archivo original
        parsed_url = urllib.parse.urlparse(pdf_url)
        original_filename = os.path.basename(parsed_url.path)
        base_filename, file_extension = os.path.splitext(original_filename)
        
        # Definir la ruta de salida para el PDF firmado
        output_path = f'{base_filename}_signed{file_extension}'
        
        # Firmar el PDF y guardarlo en la ruta de salida
        sign_pdf(pdf_data, private_key, output_path)
        
        # Devolver el PDF firmado como respuesta
        return send_file(output_path, as_attachment=True, download_name=output_path, mimetype='application/pdf')
    except Exception as e:
        logging.error(f'Error occurred: {e}', exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/hola', methods=['GET'])
def hola_mundo():
    return "Hola Mundo"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)