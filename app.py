from flask import Flask,render_template,url_for,request,redirect,flash,session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import timedelta
from flask_login import UserMixin
from flask_login import LoginManager,login_user
from sqlalchemy.sql import func
import random
import array
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import pyperclip

from password_generator import generator

from flask_login import login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secretkey = "nbshbshebdbaj"
'''
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
'''

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'ashbjhwbfhyw'
db = SQLAlchemy(app)
key = b'Sixteen byte key'

class User(db.Model, UserMixin):
	__tablename__ = "user"
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(20), nullable = False, unique = True)
	password = db.Column(db.String(80), nullable = False)
	#notes = db.relationship("Passwords")
	
	def __repr__(self):
	
		return f"UserName: {self.username}, password:{self.password}" 

class Passwords(db.Model):
	__tablename__ = "passwords"
	sl = db.Column(db.Integer, primary_key = True)	
	domainname = db.Column(db.String(20), nullable = False)
	username = db.Column(db.String(20), nullable = False)
	password = db.Column(db.String(80), nullable = False)
	#date = db.Column(db.DateTime(timezone = True),default = func.now())
	#owner = db.Column(db.Integer, db.ForeignKey('user.id'))
	
	def __repr__(self):
		return f"domainname:{self.domainname} username:{self.username} password:{self.password}"
	

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')
    return (iv, ciphertext)

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(iv))
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    decrypted_text = decrypted_bytes.decode('utf-8')
    return decrypted_text
	

@app.route('/')
def home():
	users = User.query.all()
	for user in users:
		db.session.delete(user)
		
	

	return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])

def login():
	if request.method =="POST" and 'uname' in request.form and 'pwd' in request.form:
		uname= request.form["uname"]
		
		pwd = request.form["pwd"]
		user = User.query.filter_by(username = uname).first()
		#check_password_hash(User.password,pwd)
		if user is not None and check_password_hash(user.password,pwd):
			flash(f"{uname} logged in successfully")
			#login_user(user,remember =True)
			return redirect(url_for("homelogin"))
		else:
			flash("Incorrect Username /Password")
			return redirect(url_for("login"))
	#flash('Enter all the fields')
	return render_template("login.html")
	
'''
	

@login_manager.user_loader
def load_user(user):
	return SessionUser.find_by_session_id(user_id)
'''
	
@app.route("/signup", methods = ["GET", "POST"])
def signup():
	if request.method =="POST" and 'uname' in request.form and 'pwd1' in request.form and 'pwd2' in request.form:
		uname= request.form["uname"]
		pwd1 = request.form["pwd1"]
		pwd2 = request.form["pwd2"]
		if len(uname)<6 :
			flash("Length of username should be greater then 6")
			return redirect(url_for("signup"))
		elif len(password)<8 :
			flash("Length of password should be greater then 8")
		if (pwd1==pwd2):
		
			newuser = User(username= uname,password = generate_password_hash(pwd1, method = 'sha256'))
			db.session.add(newuser)
			db.session.commit()
			return redirect(url_for("login"))
		else:
			flash("check the password again!")
			return redirect(url_for("signup"))	
	#flash('Enter all the fields')
	return render_template("signup.html") 
	
@app.route("/homelogin")
def homelogin():
	all_psws = Passwords.query.all()
	#for psw in all_psws:
	#	print(psw)
	
	return render_template("home.html",all_psws = all_psws)
	
@app.route("/manage_passwords", methods=["GET","POST"])
def manage_passwords():
	if request.method =="POST":
		dname = request.form['dname']
		userid = request.form['userid']
		psw1 = request.form['psw1']
		psw2 = request.form['psw2']
		exist_data = Passwords.query.filter_by(domainname = dname, username = userid).first()
		
		############ 
		
		plaintext = psw1
		(iv, ciphertext) = aes_encrypt(key, psw1)
		decrypted_text = aes_decrypt(key, iv, ciphertext)

		print('Plaintext:', plaintext)
		print('Encrypted:', ciphertext)
		print('Decrypted:', decrypted_text)
		
		
		
		
		
		
		###################
		
		if(psw1==psw2):
			if exist_data is None:
				newdata = Passwords(domainname = dname, username = userid,password = iv+ciphertext)
				db.session.add(newdata)
				db.session.commit()
				return redirect(url_for("manage_passwords"))
			else:
				db.session.delete(exist_data)
				newdata = Passwords(domainname = dname, username = userid,password = iv+ciphertext)
				
				db.session.add(newdata)
				db.session.commit()
				return redirect(url_for("manage_passwords"))
		else:
			flash("check the password again!")
			return redirect(url_for("manage_passwords"))
	return render_template("manage.html")
	
@app.route("/delete/<int:sno>", methods = ["GET", "POST"])
def delete(sno):
	psw = Passwords.query.filter_by(sl = sno).first()
	db.session.delete(psw)
	db.session.commit()
	return redirect(url_for("homelogin"))
	
	
@app.route("/view_decryped/<int:sno>",methods = ["GET","POST"])
def view_decrypted(sno):
	psw = Passwords.query.filter_by(sl = sno).first()
	iv = psw.password[0:24]
	ciphertext = psw.password[24:]
	decrypted_text = aes_decrypt(key, iv, ciphertext)
	psw.password = decrypted_text
	#db.session.commit()
	flash(f"{psw.password}")
	return redirect(url_for("homelogin"))	
	
@app.route("/passgen", methods = ["GET", "POST"])
def passgen():
    if "chars" not in session:
        session["chars"] = ["uppercase", "lowercase", "digits", "symbols"]
    if "len_range_value" not in session:
        session["len_range_value"] = 14
    if "secure_password" not in session:
        chars = session["chars"]
        len_range_value = session["len_range_value"]

        session["secure_password"] = generator(
            length=int(len_range_value),
            uppercase="uppercase" in chars,
            lowercase="lowercase" in chars,
            digits="digits" in chars,
            symbols="symbols" in chars,
        )

    chars = session["chars"]
    len_range_value = session["len_range_value"]
    secure_password = session["secure_password"]

    return render_template(
        "passgen.html",
        chars=chars,
        len_range_value=len_range_value,
        secure_password=secure_password,
    )


@app.route("/generate/", methods=["GET", "POST"])
def generate():
    if request.method == "POST":
        chars = request.form.getlist("char_box")
        len_range_value = request.form.get("len_range")
        secure_password = generator(
            length=int(len_range_value),
            uppercase="uppercase" in chars,
            lowercase="lowercase" in chars,
            digits="digits" in chars,
            punctuation="punctuation" in chars,
        )

        if len(chars) != 0:
            session["chars"] = chars
            session["len_range_value"] = len_range_value
            session["secure_password"] = secure_password
            return redirect(url_for("passgen"))
        else:
            return redirect(url_for("passgen"))
    else:
        return redirect(url_for("passgen"))

	
@app.route("/passstrength")
def passstrength():
	return render_template("passstrength.html")

@app.route("/logout")
def logout():
	
	return redirect(url_for("login"))
	
with app.app_context():
	db.create_all()

	
	
if __name__ == "__main__":
	app.run(debug=True)
	
