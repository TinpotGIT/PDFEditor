import os
from flask import Flask, request, render_template, Response, send_file, send_from_directory, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired)
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from werkzeug.utils import secure_filename
from io import BytesIO

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=["GET", "POST"])
def index():
    if 'user_id' in session:
        return render_template('index.html')
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('login.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            session['user_id'] = user.id
            session['username'] = username
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not username or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('login.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('login.html')
        
        if User.query.filter_by(username=username).first() is not None:
            flash('Username already exists', 'error')
            return render_template('login.html')
        
        user = User(username=username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'User {username} successfully registered', 'success')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/success', methods=['POST'])
def success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        f = request.files['file']
        username = session['username']
        file_path = os.path.join(UPLOAD_FOLDER, f'{username}.pdf')
        f.save(file_path)
        if os.stat(file_path).st_size == 0:
            os.remove(file_path)
            return redirect(url_for('index'))
        return render_template('index.html')

@app.route('/generate-pdf', methods=["GET", "POST"])
def generate_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        title = request.form.get("lname")
        username = session['username']
        pdf_path = os.path.join('uploads', f'{username}.pdf')
        
        # Generate PDF with title
        buffer = generate_pdf_file(title)
        
        # Save the PDF
        with open(pdf_path, 'wb') as f:
            f.write(buffer.getvalue())
        
        return redirect(url_for('index'))

def generate_pdf_file(title):
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica", 16)
    p.drawString(100, 750, title)
    p.showPage()
    p.save()
    buffer.seek(0)
    return buffer

@app.route('/pagepdf', methods=['GET', 'POST'])
def handle_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_page_text = request.form['pagetext']
        username = session['username']
        pdf_path = os.path.join('uploads', f'{username}.pdf')
        
        if os.path.exists(pdf_path) :
            existing_pdf = PdfReader(open(pdf_path, 'rb'))
        else:
            return redirect(url_for('index'))
        output = PdfWriter()
        
        # Get dimensions of the first page
        first_page = existing_pdf.pages[0]
        width = float(first_page.mediabox.width)
        height = float(first_page.mediabox.height)
        
        # Create new page with matching dimensions
        packet = BytesIO()
        can = canvas.Canvas(packet, pagesize=(width, height))
        
        # Render text without black squares
        text_object = can.beginText(100, height - 100)
        text_object.setFont("Helvetica", 12)
        text_object.textLines(new_page_text)  # Use textLines instead of manual line processing
        can.drawText(text_object)
        
        can.save()
        packet.seek(0)
        new_page = PdfReader(packet).pages[0]
        # Add existing pages and new page
        for page in existing_pdf.pages:
            output.add_page(page)
        output.add_page(new_page)
        
        # Save the new PDF
        with open(pdf_path, 'wb') as f:
            output.write(f)
        
        return redirect(url_for('index'))

    return render_template('index.html')

@app.route('/pdf', methods=['GET', 'POST'])
def serve_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    username = session['username']
    return send_from_directory('uploads', f'{username}.pdf')

@app.route('/upload-image', methods=['POST'])
def upload_image():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'image' not in request.files:
        return redirect(url_for('index'))
    
    image_file = request.files['image']
    if image_file.filename == '':
        return redirect(url_for('index'))
    
    username = session['username']
    pdf_path = os.path.join('uploads', f'{username}.pdf')
    
    # Read existing PDF
    existing_pdf = PdfReader(open(pdf_path, 'rb'))
    if os.path.exists(pdf_path):
        existing_pdf = PdfReader(open(pdf_path, 'rb'))
    else:
        return redirect(url_for('index'))
    output = PdfWriter()
    
    # Copy existing pages
    for page in existing_pdf.pages[:-1]:
        output.add_page(page)
    
    # Get the last page
    last_page = existing_pdf.pages[-1]
    
    # Create a new page with the image
    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=(float(last_page.mediabox.width), float(last_page.mediabox.height)))
    
    # Draw existing content
    can.setPageSize((float(last_page.mediabox.width), float(last_page.mediabox.height)))
    can.showPage()
    can.save()
    packet.seek(0)
    new_page = PdfReader(packet).pages[0]
    
    # Merge the existing content with the new page
    new_page.merge_page(last_page)
    
    # Add the image to the bottom of the page
    img = ImageReader(image_file)
    img_width, img_height = img.getSize()
    aspect = img_height / float(img_width)
    
    # Set image width to 80% of page width
    display_width = float(last_page.mediabox.width) * 0.8
    display_height = display_width * aspect
    
    # Calculate position (centered horizontally, at the bottom vertically)
    x = (float(last_page.mediabox.width) - display_width) / 2
    y = 50  # 50 points from the bottom
    
    # Draw the image
    can = canvas.Canvas(None)
    can.drawImage(img, x, y, width=display_width, height=display_height)
    image_page = PdfReader(BytesIO(can.getpdfdata())).pages[0]
    new_page.merge_page(image_page)
    
    # Add the new page
    output.add_page(new_page)
    
    # Save the new PDF
    with open(pdf_path, 'wb') as f:
        output.write(f)
    
    return redirect(url_for('index'))

@app.route('/download-pdf', methods=['GET'])
def download_pdf():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    username = session['username']
    filename = request.args.get('filename', f'{username}.pdf')  # Default name if not provided
    pdf_path = os.path.join('uploads', f'{username}.pdf')
    
    response = send_file(pdf_path, as_attachment=True)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}.pdf"' 
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)