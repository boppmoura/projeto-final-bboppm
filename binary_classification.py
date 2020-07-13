import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import cross_val_score
import numpy as np
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
from sklearn.metrics import f1_score
from sklearn import datasets
from sklearn.ensemble import ExtraTreesClassifier
import matplotlib.pyplot as plt



df = pd.read_csv('dataset-final1.csv')


X = df.drop(columns=['Vulneravel'])
y = df['Vulneravel'].values


knn2 = KNeighborsClassifier()

param_grid = {'n_neighbors': np.arange(1, 25)}
knn_gscv = GridSearchCV(knn2, param_grid, cv=5)
knn_gscv.fit(X, y)
h = knn_gscv.best_params_
j = knn_gscv.best_score_



X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state=1, stratify=y)


knn = KNeighborsClassifier(n_neighbors = j)
knn.fit(X_train,y_train)


pred = knn.predict(X_test)



confmat = confusion_matrix(y_test, pred)# Accuracy

tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()

print ("TP", tp)
print ("TN",tn)
print ("FP", fp)
print ("FN", fn)


accScore = accuracy_score(y_test, pred )# Recall
recScore = recall_score(y_test, pred, average='macro')# Precision
precScore = precision_score(y_test, pred, average='macro')
f1Score = f1_score(y_test, pred, average='macro')


print ("Matriz do modelo:", confmat)
print ("Acuracia do modelo:", accScore)
print ("Sensibilidade do modelo:", recScore)
print ("Precisao do modelo:", precScore)
print ("Score f1 do modelo:", f1Score)





X = df.iloc[:,0:5]  
y = df.iloc[:,-1]    


model = ExtraTreesClassifier()
model.fit(X,y)
print(model.feature_importances_) 
feat_importances = pd.Series(model.feature_importances_, index=X.columns)
feat_importances.nlargest(10).plot(kind='barh')
plt.show()
