import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Load the data
df = pd.read_csv("cyberthreat.csv")
columns_to_drop = ['Destination Port', 'Destination IP Address', 'Receiver ID']
df = df[~((df['Target Variable'] == 'Phishing') | 
          (df['Target Variable'] == 'Zero-Day Exploits') | 
          (df['Target Variable'] == 'Password Attacks') | 
          (df['Target Variable'] == 'DoS'))]

# Drop specified columns
df = df.drop(columns_to_drop, axis=1)

# Perform one-hot encoding for categorical variables
cols = df.columns
encoders = []
from sklearn.preprocessing import LabelEncoder
for col in cols[:-1]:
    encoder = LabelEncoder()
    df[col] = encoder.fit_transform(df[col])
    encoders.append(encoder)
    
# Split the data into features and target variable
X = df.drop('Target Variable', axis=1)
y = df['Target Variable']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the Random Forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Title of the application
st.title("Détection des cybermenaces")

# CSS style to customize the button
button_style = '''
    <style>
        .stButton>button {
            background-color: blue !important;
        }
    </style>
'''
st.markdown(button_style, unsafe_allow_html=True)

# Input fields for attack features

feature1 = st.text_input("**Protocol:**")
feature2 = st.text_input("**Flag :**")
feature3 = st.text_input("**Packet :**")
feature4 = st.text_input("**Sender ID :**")
feature5 = st.text_input("**Source IP Address :**")  
feature6 = st.text_input("**Source Port :**")  
feature7 = st.text_input("**Packet Size :**")

# Function to predict the attack with probabilities
def predict_attack_with_prob(features, threshold=0.2):
    # Predict the probabilities for each class
    probabilities = model.predict_proba(features)
    
    # Get the possible predicted classes by the model
    possible_classes = model.classes_
    
    # Initialize the predicted class with a default value
    predicted_attack = "another attack"
    
    # Loop through the predicted probabilities and compare them with the threshold
    for i, prob in enumerate(probabilities[0]):
        if prob >= threshold:
            # If the probability is greater than or equal to the threshold, predict this class
            predicted_attack = possible_classes[i]
            break  # Exit the loop as soon as a class is predicted
    
    return predicted_attack

# Button to make the prediction
if st.button("Prédire l'attaque"):
    # Create a DataFrame with the input features
    input_features_df = pd.DataFrame({
        'Protocol': [feature1],
        'Flag': [feature2],
        'Packet': [feature3],
        'Sender ID': [feature4],
        'Source IP Address': [feature5],
        'Source Port': [feature6],
        'Packet Size': [feature7]
    })

    # Encode the input features using the previously trained encoders
    for col, encoder in zip(input_features_df.columns, encoders):
        input_features_df[col] = encoder.transform(input_features_df[col])

    # Convert the DataFrame to array
    input_features = input_features_df.values

    # Make the prediction
    predicted_attack = predict_attack_with_prob(input_features)
    
    # Display the result
    st.write(f"Type d'attaque prédit : {predicted_attack}")
