import pandas as pd
import itertools
import tkinter as tk
from tkinter import simpledialog

from sklearn import metrics
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import xgboost as xgb
from lightgbm import LGBMClassifier
import os
import seaborn as sns
from wordcloud import WordCloud

ROOT = tk.Tk()

ROOT.withdraw()
# the input dialog
USER_INP = simpledialog.askstring(title="Url",
                                  prompt="Enter The URL : ")

df = pd.read_csv('C:\\Users\\Gurusamy\\PycharmProjects\\pythonProject2\\dataset\\malicious_phish.csv')
print(df.shape)
print(df.head())
print(df.type.value_counts())
df_phish = df[df.type == 'phishing']
df_malware = df[df.type == 'malware']
df_deface = df[df.type == 'defacement']
df_benign = df[df.type == 'benign']
phish_url = " ".join(i for i in df_phish.url)
wordcloud = WordCloud(width=1600, height=800, colormap='Paired').generate(phish_url)
# plt.figure(figsize=(12, 14), facecolor='k')
# plt.imshow(wordcloud, interpolation='bilinear')
# plt.axis("off")
# plt.tight_layout(pad=0)
# plt.show()
malware_url = " ".join(i for i in df_malware.url)
wordcloud = WordCloud(width=1600, height=800, colormap='Paired').generate(malware_url)
# plt.figure(figsize=(12, 14), facecolor='k')
# plt.imshow(wordcloud, interpolation='bilinear')
# plt.axis("off")
# plt.tight_layout(pad=0)
# plt.show()
deface_url = " ".join(i for i in df_deface.url)
wordcloud = WordCloud(width=1600, height=800, colormap='Paired').generate(deface_url)
# plt.figure(figsize=(12, 14), facecolor='k')
# plt.imshow(wordcloud, interpolation='bilinear')
# plt.axis("off")
# plt.tight_layout(pad=0)
# plt.show()
benign_url = " ".join(i for i in df_benign.url)
wordcloud = WordCloud(width=1600, height=800, colormap='Paired').generate(benign_url)
# plt.figure(figsize=(12, 14), facecolor='k')
# plt.imshow(wordcloud, interpolation='bilinear')
# plt.axis("off")
# plt.tight_layout(pad=0)
# plt.show()
import re
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
from urllib.parse import urlparse

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
from googlesearch import search
def google_index(url):
    site = search()
    return 1 if site else 0
df['google_index'] = df['url'].apply(lambda i: google_index(i))
def count_dot(url):
    count_dot = url.count('.')
    return count_dot

df['count.'] = df['url'].apply(lambda i: count_dot(i))
print(df.head())


def count_www(url):
    url.count('www')
    return url.count('www')


df['count-www'] = df['url'].apply(lambda i: count_www(i))


def count_atrate(url):
    return url.count('@')


df['count@'] = df['url'].apply(lambda i: count_atrate(i))


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')


df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))


def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')


df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))


def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0


df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
def count_https(url):
    return url.count('https')

df['count-https'] = df['url'].apply(lambda i : count_https(i))

def count_http(url):
    return url.count('http')

df['count-http'] = df['url'].apply(lambda i : count_http(i))
def count_per(url):
    return url.count('%')

df['count%'] = df['url'].apply(lambda i : count_per(i))

def count_ques(url):
    return url.count('?')

df['count?'] = df['url'].apply(lambda i: count_ques(i))

def count_hyphen(url):
    return url.count('-')

df['count-'] = df['url'].apply(lambda i: count_hyphen(i))

def count_equal(url):
    return url.count('=')

df['count='] = df['url'].apply(lambda i: count_equal(i))

def url_length(url):
    return len(str(url))


#Length of URL
df['url_length'] = df['url'].apply(lambda i: url_length(i))
#Hostname Length

def hostname_length(url):
    return len(urlparse(url).netloc)
df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))

df.head()

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0
df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


df['count-digits']= df['url'].apply(lambda i: digit_count(i))


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


df['count-letters']= df['url'].apply(lambda i: letter_count(i))

print(df.head())
from urllib.parse import urlparse
from tld import get_tld
import os.path

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

df['fd_length'] = df['url'].apply(lambda i: fd_length(i))

#Length of Top Level Domain
df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))


def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
df = df.drop("tld",1)
print(df.columns)
print(df['type'].value_counts())
import seaborn as sns
print(sns.set(style="darkgrid"))
print(sns.countplot(y="type", data=df,hue="use_of_ip"))
print(sns.set(style="darkgrid"))
print(sns.countplot(y="type", data=df,hue="abnormal_url"))
print(sns.set(style="darkgrid"))
print(sns.countplot(y="type", data=df,hue="google_index"))
print(sns.set(style="darkgrid"))
print(sns.countplot(y="type", data=df,hue="short_url"))
print(sns.set(style="darkgrid"))
print(sns.countplot(y="type", data=df,hue="sus_url"))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="count.", kind="box", data=df))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="count-www", kind="box", data=df))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="count@", kind="box", data=df))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="count_dir", kind="box", data=df))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="hostname_length", kind="box", data=df))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="fd_length", kind="box", data=df))
print(sns.set(style="darkgrid"))
print(sns.catplot(x="type", y="tld_length", kind="box", data=df))
from sklearn.preprocessing import LabelEncoder

lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])
print(df["type_code"].value_counts())
X = df[['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@',
       'count_dir', 'count_embed_domian', 'short_url', 'count-https',
       'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
       'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
       'count-letters']]

#Target Variable
y = df['type_code']
print(X.head())
print(X.columns)
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2,shuffle=True, random_state=5)
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=100,max_features='sqrt')
print(rf.fit(X_train,y_train))
y_pred_rf = rf.predict(X_test)
print(classification_report(y_test,y_pred_rf,target_names=['benign', 'defacement','phishing','malware']))

score = metrics.accuracy_score(y_test, y_pred_rf)
print("accuracy:   %0.3f" % score)
cm = confusion_matrix(y_test, y_pred_rf)
cm_df = pd.DataFrame(cm,
                     index = ['benign', 'defacement','phishing','malware'],
                     columns = ['benign', 'defacement','phishing','malware'])
print(plt.figure(figsize=(8,6)))
print(sns.heatmap(cm_df, annot=True,fmt=".1f"))
print(plt.title('Confusion Matrix'))
print(plt.ylabel('Actal Values'))
print(plt.xlabel('Predicted Values'))
# plt.show()
feat_importances = pd.Series(rf.feature_importances_, index=X_train.columns)
print(feat_importances.sort_values().plot(kind="barh",figsize=(10, 6)))
lgb = LGBMClassifier(objective='multiclass',boosting_type= 'gbdt',n_jobs = 5,
          silent = True, random_state=5)
LGB_C = lgb.fit(X_train, y_train)


y_pred_lgb = LGB_C.predict(X_test)
print(classification_report(y_test,y_pred_lgb,target_names=['benign', 'defacement','phishing','malware']))

score = metrics.accuracy_score(y_test, y_pred_lgb)
print("accuracy:   %0.3f" % score)
cm = confusion_matrix(y_test, y_pred_lgb)
cm_df = pd.DataFrame(cm,
                     index = ['benign', 'defacement','phishing','malware'],
                     columns = ['benign', 'defacement','phishing','malware'])
print(plt.figure(figsize=(8,6)))
print(sns.heatmap(cm_df, annot=True,fmt=".1f"))
print(plt.title('Confusion Matrix'))
print(plt.ylabel('Actal Values'))
print(plt.xlabel('Predicted Values'))
# plt.show()
feat_importances = pd.Series(lgb.feature_importances_, index=X_train.columns)
print(feat_importances.sort_values().plot(kind="barh",figsize=(10, 6)))
xgb_c = xgb.XGBClassifier(n_estimators= 100)
print(xgb_c.fit(X_train,y_train))
y_pred_x = xgb_c.predict(X_test)
print(classification_report(y_test,y_pred_x,target_names=['benign', 'defacement','phishing','malware']))


score = metrics.accuracy_score(y_test, y_pred_x)
print("accuracy:   %0.3f" % score)
cm = confusion_matrix(y_test, y_pred_x)
cm_df = pd.DataFrame(cm,
                     index = ['benign', 'defacement','phishing','malware'],
                     columns = ['benign', 'defacement','phishing','malware'])
print(plt.figure(figsize=(8,6)))
print(sns.heatmap(cm_df, annot=True,fmt=".1f"))
print(plt.title('Confusion Matrix'))
print(plt.ylabel('Actal Values'))
print(plt.xlabel('Predicted Values'))
# plt.show()
feat_importances = pd.Series(xgb_c.feature_importances_, index=X_train.columns)
print(feat_importances.sort_values().plot(kind="barh",figsize=(10, 6)))


def main(url):
    status = []

    print(status.append(having_ip_address(url)))
    print(status.append(abnormal_url(url)))
    print(status.append(count_dot(url)))
    print(status.append(count_www(url)))
    print(status.append(count_atrate(url)))
    print(status.append(no_of_dir(url)))
    print(status.append(no_of_embed(url)))

    print(status.append(shortening_service(url)))
    print(status.append(count_https(url)))
    print(status.append(count_http(url)))

    print(status.append(count_per(url)))
    print(status.append(count_ques(url)))
    print(status.append(count_hyphen(url)))
    print(status.append(count_equal(url)))

    print(status.append(url_length(url)))
    print(status.append(hostname_length(url)))
    print(status.append(suspicious_words(url)))
    print(status.append(digit_count(url)))
    print(status.append(letter_count(url)))
    print(status.append(fd_length(url)))
    tld = get_tld(url, fail_silently=True)

    print(status.append(tld_length(tld)))

    return status


def get_prediction_from_url(test_url):
    features_test = main(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))

    pred = lgb.predict(features_test)
    if int(pred[0]) == 0:

        res = "SAFE"
        return res
    elif int(pred[0]) == 1.0:

        res = "DEFACEMENT"
        return res
    elif int(pred[0]) == 2.0:
        res = "PHISHING"
        return res

    elif int(pred[0]) == 3.0:

        res = "MALWARE"
        return res


# urls = ['titaniumcorporate.co.za', 'en.wikipedia.org/wiki/North_Dakota']

# for url in urls:
#     print(get_prediction_from_url(url))
print("1.Executed")

print(get_prediction_from_url(USER_INP))

if __name__ == '__main__':
    pass
