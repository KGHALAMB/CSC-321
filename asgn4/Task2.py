from PyPDF2 import PdfReader
import bcrypt
import time
import nltk
nltk.download('words')
from nltk.corpus import words

start_time = time.time()
word_list = words.words()
filtered_words = [word for word in word_list if len(word) >= 6 and len(word) <= 10]
filtered_words.sort()


# Open the PDF file in binary mode
#with open('shadow.pdf', 'rb') as f:
# Create a PDF reader object
pdf_reader = PdfReader('shadow.pdf')

# Get the total number of pages in the PDF file
num_pages = len(pdf_reader.pages)

page = pdf_reader.pages[0]
text = page.extract_text()
lines = text.split('\n')

i = 0
for line in lines:
    parts = line.split('$')
    i += 1
    if i == 2:
        break
print(parts)

#Test
'''
test_word = "registrationsucks"
test_encode = "$2b$08$J9FW66ZdPI2nrIMcOxFYI."
ret = bcrypt.hashpw(test_word.encode('utf-8'), test_encode.encode('utf-8'))
print(ret)

print(bcrypt.checkpw(test_word.encode('utf-8'), ret))
'''

name = parts[0]
salthash = '$' + parts[1] + '$' + parts[2] + '$' + parts[3]
salthash = salthash.strip()
sh = salthash.encode('utf-8')

print(name + " " + salthash)

for word in filtered_words:
    ret = bcrypt.hashpw(word.encode('utf-8'), sh)
    #print(ret)
    #print(sh)
    if ret == sh:
        print(name + " " + word)
        break
    
end_time = time.time() - start_time
print(end_time)