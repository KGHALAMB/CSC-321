from PyPDF2 import PdfReader
import bcrypt
import time
import nltk
nltk.download('words')
from nltk.corpus import words

start_time = time.time()
word_list = words.words()
filtered_words = [word for word in word_list if len(word) >= 6 and len(word) <= 10]


# Open the PDF file in binary mode
#with open('shadow.pdf', 'rb') as f:
# Create a PDF reader object
pdf_reader = PdfReader('shadow.pdf')

# Get the total number of pages in the PDF file
num_pages = len(pdf_reader.pages)

page = pdf_reader.pages[0]
text = page.extract_text()
lines = text.split('\n')
for line in lines:
    parts = line.split('$')
print(parts)

#Test
test_word = "registrationsucks"
test_encode = "$2b$08$J9FW66ZdPI2nrIMcOxFYI."
ret = bcrypt.hashpw(test_word.encode('utf-8'), test_encode.encode('utf-8'))
print(ret)

print(bcrypt.checkpw(test_word.encode('utf-8'), ret))

name = parts[0]
salthash = '$' + parts[1] + '$' + parts[2] + '$' + parts[3]
print(name)
print(salthash)
for word in filtered_words:
    if bcrypt.checkpw(word.encode('utf-8'), salthash.encode('utf-8')):
        print(name)
        print(word) 
        break

end_time = time.time() - start_time
print(end_time)