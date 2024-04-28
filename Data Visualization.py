import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud
import sqlite3

## Read the dataset (csv file) from Kaggle
url = 'https://drive.google.com/file/d/1W4_6_Et46AUFy9kQoCsFv480Yg2_FVqK/view?usp=sharing'
url = 'https://drive.google.com/uc?id=' + url.split('/')[-2]
df = pd.read_csv(url)

# Get the statistics of all the columns and rows in the dataset
print("The total number of columns:", df.shape [1])
print("The total number of rows:", df.shape[0])
print(df.head(10))
print(df.describe(include=['object']))

## Data Cleaning
# Checking for duplicates
duplicates = df.duplicated()

# Counting the total number of duplicates
num_duplicates = duplicates.sum()
print("Number of duplicates:", num_duplicates)
print("Rows with duplicates:")
print(df[duplicates])

# Checking the datatype of each column
for column_name in df.columns:
     data_type = df[column_name].dtype
     is_categorical = isinstance(data_type, pd.CategoricalDtype)
     is_numeric = pd.api.types.is_numeric_dtype(data_type)
     print(f"column '{column_name}' - Data Type: {data_type}, Categorical: {is_categorical}, Numeric: {is_numeric}")

# Check for missing values
missing_values = df.isnull().sum()
print("Missing values count for each column:", missing_values)

# Checking the datatype of each column
for column_name in df .columns:
    data_type = df[column_name].dtype
    is_categorical = isinstance(data_type, pd.CategoricalDtype)
    is_numerical = pd.api.types.is_numeric_dtype(data_type)
    print (f"Column '{column_name}' Data Type: {data_type}, Categorical: {is_categorical}, Numeric: {is_numeric}")

# Inputting the missing values with mode
df['Malware Indicators'] = df['Malware Indicators'].fillna(df['Malware Indicators'].mode()[0])
df['Alerts/Warnings'] = df['Alerts/Warnings'].fillna(df['Alerts/Warnings'] .mode()[0])
df['Proxy Information'] = df['Proxy Information'].fillna(df['Proxy Information'].mode()[0])
df['Firewall Logs'] = df['Firewall Logs'].fillna(df['Firewall Logs'].mode()[0])
df['IDS/IPS Alerts'] = df['IDS/IPS Alerts'].fillna(df['IDS/IPS Alerts']. mode()[0])

# Drop Payload column (irrelevant)
df = df.drop(labels='Payload Data', axis=1)

# Drop column if it has more than 90% of its data missing
df_cleaned = df.dropna(thresh=len(df) * 0.1, axis=1)


#### VISUALISATIONS ####
# Visualisation: Word Cloud
columns = ['Attack Type', 'Malware Indicators', 'Firewall Logs', 'Log Source', 'Geo-location Data']

#obtain the data from the selected column
data = df[columns]

#Convert the data to a string format
text = " ".join(str(value) for column in data.columns for value in data[column])

# Generate the word cloud
wordcloud = WordCloud(width=800, height=400, background_color='white').generate(text)

# Display the word cloud
plt. figure(figsize=(10, 8))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.show()


# Visualisation: Attack Analysis
attack_type_counts = df['Attack Type'].value_counts()
print("Distribution of Attack Types:", attack_type_counts)

# Obtain data for the pie chart
sizes = df['Attack Type'].value_counts()

# Setting custom colours and explode parameter
custom_colours = sns.color_palette('Accent')
explode = [0] * (len(attack_type_counts) - 1) + [0.1]

# Plotting the different distributions of the attack analysis in a pie chart
plt.figure(figsize=(8, 8))
plt.pie(attack_type_counts, labels=attack_type_counts.index, autopct='%1.1f%%', startangle=9, colors=custom_colours, explode= explode)
plt. title(label='Distribution of Attack Types', fontsize=20, fontweight='bold')
plt.axis('equal')
plt.show()


# Visualisation: Plotting a point plot- Severity levels of the attack in a line chart
# Obtain the counts of the Dataframe to avoid modifying the original
severity_level_counts = df["Severity Level"].value_counts()
print("\nDistribution of Severity Levels:", severity_level_counts)

# Create a copy of the DataFrame to avoid modifying the original
df_copy = df.copy()
# encoding the categorical variables into numerical values
df_copy["Severity Level"] = pd.factorize(df["Severity Level"])[0]

# Creating point plots for the severity levels
sns.pointplot(data=df_copy, x="Severity Level", y="Attack Type", hue="Attack Type", markers="o", linestyles="")
plt.title("Severity Level vs Attack Type")
plt.xlabel("Severity Level")
plt.ylabel("Attack Type")
plt.legend(title="Attack Type", loc="upper right")
plt.show()


# Visualisation: Heatmap
# Analysing the relationship between the Attack Type and Severity level
# Creating a cross-tabulation of Attack Type and Severity Level
cross_tab = pd.crosstab(df['Attack Type'], df[ 'Severity Level'])

# Plotting a heatmap
plt. figure(figsize=(10, 6))
sns.heatmap(cross_tab, annot=True, cmap='coolwarm', fmt='d')
plt.title('Relationship between Attack Type and Severity Level')
plt.xlabel('Severity Level')
plt.ylabel('Attack Type')
plt.show()


# Visualisation: Line Chart
# Performing Temporal Analysis to identify attack Patterns over time
# Converting the Timestamp column to Pandas datetime series.
df['Timestamp'] = pd. to_datetime(df['Timestamp'])
# Resample the data by month and count the number of attacks per month
monthly_attacks = df.resample(rule='ME', on='Timestamp')['Attack Type'].count()

# Plot the number of attacks by month
monthly_attacks.plot(color='orange', figsize=(10, 6))
plt.title('Number of Attacks per Month')
plt.ylabel('Number of Attacks')
plt.show()


# Visualisation: Box Plot
# Anomaly Scores on Attack Type
plt.figure(figsize=(12, 6))
sns.boxplot(data=df, x='Anomaly Scores', y='Attack Type', hue='Attack Type', showfliers=False)
plt. title(f'Distribution of Anomaly Scores by Attack Type')
plt.xlabel(xlabel='Anomaly Scores', fontsize=14, fontweight='bold')
plt.ylabel(ylabel='Attack Type', fontsize=14, fontweight= 'bold')
plt.show()


# Visualisation: Count Plot
# Countplot Attack Type & Action Taken import
sns.countplot(data=df, x='Action Taken', hue='Attack Type')
plt.show()


# Visualisation: Scatter Plot
# Incident Response Analysis
threshold = 90
df['Anomaly'] = df['Anomaly Scores'] > threshold
plt.figure(figsize=(10, 6))
sns.scatterplot(data=df, x='Timestamp', y='Anomaly Scores', hue='Anomaly')
plt.title('Anomaly Scores Over Time')
plt.xlabel('Timestamp')
plt.ylabel('Anomaly Scores')
plt.show()


# Visualisation: Horizontal Bar chart - users according to Alert count
# Check for unique actions + categorizing to identify suspicious ones
print('Columns from Action Taken:', df['Action Taken'].unique())
# Filtering out suspicious activities
suspicious_df = df[df['Action Taken'].isin(['Blocked', 'Alerted'])]

# Grouping the data by 'User Information' to count the number of alerts per user
user_alert_counts = df.groupby('User Information').size()

# Find the people with highest alert count
max_alert_count = user_alert_counts.max()

# Output the results of finding the people with highest alert count
print(f"The highest alert count for any user is: {max_alert_count}")

# finding the user(s) with this highest count
users_with_max_alerts = user_alert_counts[user_alert_counts == max_alert_count]
print("User(s) with the highest alert count:")
print(users_with_max_alerts)

# Sort the alert counts in descending order and getting the top 10
top_user_alert_counts = user_alert_counts.sort_values(ascending=False).head(10)

# Plotting the data
plt.figure(figsize=(10, 7))
colors = plt.cm.viridis(np.linspace(0, 1, len(top_user_alert_counts)))  # Generate a color gradient for the bars
top_user_alert_counts.sort_values().plot(kind='barh', color=colors)  # Plot as a horizontal bar chart
plt.xlabel('Number of Alerts')
plt.ylabel('User Information- Names')
plt.title('Top 10 Users by Number of Alerts')
plt.grid(True, linestyle='--', alpha=0.5)  # Add light grid lines for better readability
plt.show()


# Visualisation: Horizontal bar chart showing laptops with the highest number of alert count according to device model
# Count the occurrences of each device in the alerts
device_alert_counts = df.groupby('Device Information').size()

# Sort the alert counts in descending order and get the top devices
top_device_alert_counts = device_alert_counts.sort_values(ascending=False).head(10)

# Plotting the data
plt.figure(figsize=(10, 7))
colors = plt.cm.viridis(np.linspace(0, 1, len(top_device_alert_counts)))  # Generate a color gradient for the bars
top_device_alert_counts.sort_values().plot(kind='barh', color=colors)
plt.xlabel('Number of Alerts')
plt.ylabel('Device Information')
plt.title('Top 10 Devices by Number of Alerts')
plt.grid(True, linestyle='--', alpha=0.5)
plt.show()


# Visualisation: Line Plot
# Resample data to get the monthly count of alerts/warnings for each attack type
alerts_over_time = df.resample('ME', on="Timestamp")["Attack Type"].value_counts().unstack(fill_value=0)

# Create a line plot for each attack type with monthly resampling
alerts_over_time.plot(kind='line', figsize=(12, 6), lw=2)

plt.xlabel("Month")
plt.ylabel("Number of Alerts")
plt.title("Alert Types Over Time (Monthly)")
plt.show()

# Visualisation: Stacked Bar Plot
# Create a pivot table for traffic type and protocol
protocol_traffic_pivot = df.pivot_table(index="Traffic Type", columns="Protocol", aggfunc='count', values="Timestamp")

# Create a stacked bar plot
protocol_traffic_pivot.plot(kind='bar', stacked=True, figsize=(12, 6))

plt.xlabel("Traffic Type")
plt.ylabel("Count")
plt.title("Stacked Bar Plot for Traffic Type and Protocol")
plt.show()


# Visualisation: Stacked Bar Plot
# Stacked bar plot for packet types and actions taken (without blanks)
plt.figure(figsize=(12, 6))
sns.histplot(df, x='Packet Type', hue='Action Taken', multiple='stack', shrink=0.8, palette='pastel')
plt.title('Packet Types and Actions Taken (Cleaned)')
plt.xlabel('Packet Type')
plt.ylabel('Count')
plt.show()



# Visualisation: HeatMap
# Create a crosstab for the heatmap
heatmap_data = pd.crosstab(df['Alerts/Warnings'], df['Severity Level'])

# Heatmap showing the relationship between Alerts/Warnings and Severity Level
plt.figure(figsize=(12, 6))
sns.heatmap(heatmap_data, annot=True, fmt="d", cmap='YlGnBu')  # 'annot=True' to display values, 'fmt="d"' for integer format
plt.title('Heatmap of Alerts/Warnings by Severity Level')
plt.xlabel('Severity Level')
plt.ylabel('Alerts/Warnings')

# Proper layout to avoid overlapping
plt.tight_layout()
plt.show()

df = pd.read_csv(url)
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Connect to the SQLite database and write the data
conn = sqlite3.connect('cybersecurity_attacks.db')
df.to_sql('attacks', conn, if_exists='replace', index=False)

# Query to calculate the weekly average for numerical columns
numerical_columns = df.select_dtypes(include=[np.number]).columns.tolist()
query_avg = "SELECT strftime('%Y-%W', Timestamp) as Week,"
query_avg += ", ".join([f"AVG(\"{col}\") as Avg_{col.replace(' ', '_')}" for col in numerical_columns])
query_avg += " FROM attacks GROUP BY Week ORDER BY Week;"
weekly_avg_df = pd.read_sql_query(query_avg, conn)

# Query to calculate the count of actions by attack type per week
query_counts = """
SELECT 
    strftime('%Y-%W', Timestamp) as Week,
    "Attack Type",
    "Action Taken",
    COUNT(*) as Count
FROM 
    attacks
GROUP BY 
    Week, "Attack Type", "Action Taken"
ORDER BY 
    Week, "Attack Type", "Action Taken";
"""
weekly_counts_df = pd.read_sql_query(query_counts, conn)

# Query to calculate the weekly average 'Anomaly Scores' for each 'Severity Level'
query_severity = """
SELECT 
    strftime('%Y-%W', Timestamp) as Week,
    "Severity Level",
    AVG("Anomaly Scores") as Avg_Anomaly_Scores
FROM 
    attacks
GROUP BY 
    Week, "Severity Level";
"""
weekly_severity_avg_df = pd.read_sql_query(query_severity, conn)

# Close the SQLite connection
conn.close()

# Plotting functions
def plot_scatter_matrix(df_subset, title):
    fig, ax = plt.subplots(figsize=(12, 12))  # Create a figure and a grid of subplots
    pd.plotting.scatter_matrix(df_subset, alpha=0.2, ax=ax, diagonal='kde')
    fig.suptitle(title, fontsize=16)  # Add a main title to the figure

def plot_stacked_bar(df, week_column, sub_category):
    pivot_table = df.pivot_table(index=week_column, columns=sub_category, values='Count', aggfunc='sum', fill_value=0)
    pivot_table.plot(kind='bar', stacked=True, figsize=(20, 6))
    plt.title(f'Stacked Bar Chart of {sub_category} over Weeks')
    plt.ylabel('Count')
    plt.xlabel('Week')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

def plot_violin(df, category, avg_numeric):
    plt.figure(figsize=(12, 6))
    sns.violinplot(x=category, y=avg_numeric, data=df, palette="muted", inner=None)  # Set inner=None to remove the bars inside the violins
    sns.swarmplot(x=category, y=avg_numeric, data=df, color='k', alpha=0.6)  # Add a swarmplot to show individual points
    avg_numeric = avg_numeric.replace('_', ' ')
    plt.title(f'Violin Plot of Weekly {avg_numeric} by {category} with Outliers')
    plt.show()


def plot_area_chart(df, week_column, avg_column):
    df[week_column] = pd.to_datetime(df[week_column] + '-0', format='%Y-%W-%w')
    df.set_index(week_column, inplace=True)
    df[avg_column].plot.area(alpha=0.4)
    avg_column = avg_column.replace('_', ' ')
    plt.title(f'Area Chart of {avg_column} over Time')
    plt.ylabel(avg_column)
    plt.xlabel('Date')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

# Call plotting functions
plot_scatter_matrix(weekly_avg_df.drop('Week', axis=1), "Weekly Average Metrics Scatter Matrix")
plot_stacked_bar(weekly_counts_df, 'Week', 'Action Taken')
plot_area_chart(weekly_avg_df[['Week', 'Avg_Anomaly_Scores']], 'Week', 'Avg_Anomaly_Scores')
# Ensure the 'Avg_Anomaly_Scores' column is of type float for the violin plot
weekly_severity_avg_df['Avg_Anomaly_Scores'] = weekly_severity_avg_df['Avg_Anomaly_Scores'].astype(float)
# Call the plotting function for the aggregated weekly average data
plot_violin(weekly_severity_avg_df, 'Severity Level', 'Avg_Anomaly_Scores')
