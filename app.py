import requests
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from PyPDF2 import PdfFileReader, PdfFileWriter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import io
import os
import urllib.parse
import logging
import qrcode
from PIL import Image
import tempfile
from datetime import datetime
import pytz

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

def get_signer_name(certificate):
    subject = certificate.subject
    common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    return common_name

def download_image(url):
    response = requests.get(url)
    response.raise_for_status()
    return Image.open(io.BytesIO(response.content))

def add_white_background(image):
    # Convertir la imagen a RGBA si no lo está
    if image.mode != 'RGBA':
        image = image.convert('RGBA')
    
    # Crear una imagen en blanco del mismo tamaño
    white_background = Image.new('RGBA', image.size, (255, 255, 255, 255))
    
    # Componer la imagen sobre el fondo blanco
    composite = Image.alpha_composite(white_background, image)
    
    # Convertir de nuevo a RGB (sin canal alfa)
    return composite.convert('RGB')

def download_pdf(pdf_url):
    response = requests.get(pdf_url)
    response.raise_for_status()  # Asegurarse de que la descarga fue exitosa
    return response.content

def sign_pdf(pdf_data, private_key,certificate,logo_url, output_path):
    # Leer el PDF
    pdf_reader = PdfFileReader(io.BytesIO(pdf_data))
    pdf_writer = PdfFileWriter()
    
    # Agregar todas las páginas al PdfFileWriter
    for page_num in range(pdf_reader.getNumPages()):
        pdf_writer.addPage(pdf_reader.getPage(page_num))
    
    # Crear un QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data('Firma Digital')
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    
    # Guardar la imagen en un archivo temporal
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp_file:
        img.save(tmp_file, format='PNG')
        tmp_file_path = tmp_file.name

    # Obtener el nombre del firmante desde el certificado
    signer_name = get_signer_name(certificate)
    
    # Dividir el nombre y apellido en dos líneas
    name_parts = signer_name.split()
    if len(name_parts) >= 4:
        first_line = ' '.join(name_parts[:2])
        second_line = ' '.join(name_parts[2:])
    else:
        first_line = name_parts[0]
        second_line = ' '.join(name_parts[1:])
    
     # Descargar el logo
    logo = download_image(logo_url)
    logo_with_background = add_white_background(logo)
    logo_tempfile = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    logo_with_background.save(logo_tempfile, format='PNG')
    logo_tempfile_path = logo_tempfile.name
 
     # Obtener la hora actual en la zona horaria de Ecuador
    ecuador_tz = pytz.timezone('America/Guayaquil')
    ecuador_now = datetime.now(ecuador_tz)
    current_date = ecuador_now.strftime("%d/%m/%Y %H:%M")
    
    # Crear un lienzo para la anotación de firma
    packet = io.BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)

    # Dibujar la imagen del QR en el lienzo
    can.drawImage(tmp_file_path, 100, 100, width=80, height=80)

     # Dibujar el logo al lado del QR
    can.drawImage(logo_tempfile_path, 300, 130, width=50, height=50)


    can.setFont("Times-Bold", 7)
    # Agregar texto al lado de la imagen del QR
    can.drawString(175, 160, "Firmado digitalmente por")
    can.setFont("Times-Bold", 8)
    can.drawString(175, 150, first_line)
    can.drawString(175, 140, second_line)
    # Dibujar la fecha actual debajo del nombre
    can.drawString(175, 130, current_date)

    can.save()

    # Mover el lienzo al inicio del buffer
    packet.seek(0)
    new_pdf = PdfFileReader(packet)

    # Obtener la última página y agregar la anotación de firma
    last_page = pdf_writer.getPage(pdf_reader.getNumPages() - 1)
    last_page.mergePage(new_pdf.getPage(0))
    
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
        logo_url = request.form.get('logo_url')
        
        logging.debug(f'Received P12_URL: {p12_url}')
        logging.debug(f'Received P12_PASSWORD: {p12_password}')
        logging.debug(f'Received pdf_url: {pdf_url}')
        logging.debug(f'Received logo_url: {logo_url}')
        
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
        sign_pdf(pdf_data, private_key, certificate,logo_url,output_path)
        
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