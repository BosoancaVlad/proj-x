from flask import Flask, render_template, request
from bloom_filter2 import BloomFilter
from zxcvbn import zxcvbn
import os

app = Flask(__name__)
filename="rockyou.txt"

    #   BLOOM FILTER
bloom = BloomFilter(max_elements=15000000, error_rate=0.001)

print("-" * 50)
print("SYSTEM STARTUP: Initialization in progress...")
print("-" * 50)

try:
    #reading progress of the txt file
    print("Loading " + filename + "... (This takes about 2 minutes)")
    count = 0
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            bloom.add(line.strip())
            count += 1
            if count % 1000000 == 0:
                print(f" -> Processed {count} passwords...")

    print(f"SUCCESS: Database loaded with {count} passwords!")

except FileNotFoundError:
    print("ERROR: " + filename + " not found. Please make sure it is in the same folder.")

print("-" * 50)


#app logic`
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None

    if request.method == 'POST':
        password = request.form['password']

        stats = zxcvbn(password)
        is_leaked = password in bloom

        #results from zxcvbn
        result = {
            'password': password,
            'score': stats['score'],
            'guesses': stats['guesses'],
            'leaked': is_leaked,
            'feedback': stats['feedback']['warning'] or "None",
            'suggestions': stats['feedback']['suggestions']
        }

    return render_template('index.html', result=result)


if __name__ == '__main__':
    #to see errors in the browser
    app.run(debug=True)