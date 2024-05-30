from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from bs4 import BeautifulSoup
import requests
from difflib import get_close_matches
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Create the database within an application context
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'username' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/compare', methods=['GET', 'POST'])
def compare():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        product = request.form['product']
    else:
        product = request.args.get('product')
    key = '+'.join(product.split())
    flipkart_results = price_flipkart(key)
    amazon_results = price_amzn(key)
    return render_template('results.html', product=product, flipkart_results=flipkart_results, amazon_results=amazon_results)

def price_flipkart(key):
    url_flip = f'https://www.flipkart.com/search?q={key}'
    map = defaultdict(list)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'
    }
    source_code = requests.get(url_flip, headers=headers)

    if source_code.status_code != 200:
        print(f"Failed to fetch data from Flipkart, status code: {source_code.status_code}")
        return {}

    soup = BeautifulSoup(source_code.text, "html.parser")
    home = 'https://www.flipkart.com'

    print("Fetching data from Flipkart...")

    for item in soup.find_all('div', {'class': '_1AtVbE'}):
        try:
            out = item.find('a', {'class': '_1fQZEK'})
            if out:
                title = out.find('div', {'class': '_4rR01T'}).text if out.find('div', {'class': '_4rR01T'}) else None
                link = home + out.get("href")
                price = item.find('div', {'class': '_30jeq3 _1_WHN1'}).text if item.find('div', {'class': '_30jeq3 _1_WHN1'}) else None

                if title and price:
                    map[title] = [price, link]
                    print(f"Found item: {title}, {price}, {link}")
                else:
                    print("Title or price not found, skipping item")

        except Exception as e:
            print(f"Error occurred: {e}")
            continue

    user_input = key.replace('+', ' ').title()
    matches_flip = get_close_matches(user_input, map.keys(), 20, 0.1)
    looktable_flip = {title: map[title] for title in matches_flip}

    print(f"Matched Flipkart items: {looktable_flip}")

    return looktable_flip

def price_amzn(key):
    url_amzn = f'https://www.amazon.in/s?k={key}'
    headers = {
        'authority': 'www.amazon.in',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',
        'dnt': '1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-dest': 'document',
        'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
    }

    map = defaultdict(list)
    home = 'https://www.amazon.in'
    source_code = requests.get(url_amzn, headers=headers)
    plain_text = source_code.text
    soup = BeautifulSoup(plain_text, "html.parser")

    print("Fetching data from Amazon...")

    for item in soup.find_all('div', {'class': 's-result-item'}):
        try:
            title = item.h2.text if item.h2 else None
            link = home + item.h2.a.get("href") if item.h2 and item.h2.a else None
            price = item.find('span', {'class': 'a-price-whole'}).text if item.find('span', {'class': 'a-price-whole'}) else None

            if title and price:
                map[title] = [price, link]
                print(f"Found item: {title}, {price}, {link}")
            else:
                print("Title or price not found, skipping item")

        except Exception as e:
            print(f"Error occurred: {e}")
            continue

    user_input = key.replace('+', ' ').title()
    matches_amzn = get_close_matches(user_input, map.keys(), 20, 0.1)
    looktable_amzn = {title: map[title] for title in matches_amzn}

    print(f"Matched Amazon items: {looktable_amzn}")

    return looktable_amzn

if __name__ == '__main__':
    app.run(debug=True)
