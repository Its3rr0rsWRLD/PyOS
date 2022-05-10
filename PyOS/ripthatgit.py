import requests
import webbrowser

print('')
print('Give a topic.')
print('')
answer = input()

# Get the topic and look it up on GitHub.
url = 'https://api.github.com/search/repositories?q=' + answer
# Get the source code of the URL.
response = requests.get(url)

# Decode the source code into a dictionary.
source = response.json()

# Get the number of repositories.
total_count = source['total_count']
print('')
print('There are ' + str(total_count) + ' repositories on GitHub with the topic ' + answer + '.')
print('')
print('Do you want to install ALL of them? (y/n)')
print('')
answer = input()
if answer == 'y':
    print('')
    print('Installing...')
    print('')
    # Get every url that is connected to html_url
    for i in range(0, total_count):
        print('Installing ' + source['items'][i]['html_url'] + '...')
        webbrowser.open(source['items'][i]['html_url'] + '/archive/master.zip')
    print('')
    print('Done!')
    print('')