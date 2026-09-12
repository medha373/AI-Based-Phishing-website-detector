# AI-Based-Phishing-website-detector

An ML model that classifies whether a website URL is legitimate or potentially phishing, based on structural URL features.

## Overview
This project uses a supervised machine learning approach to detect phishing URLs without needing to visit the site — classification is done purely from the structure of the URL itself.

## Features Used
The model extracts the following features from each URL:
- URL length
- Hostname length
- Path length
- Number of dots (`.`)
- Number of hyphens (`-`)
- Number of slashes (`/`)
- Number of `@` symbols
- Number of digits
- Other structural indicators (e.g. presence of HTTPS, special characters)

## Model
Built using **scikit-learn**. The pipeline includes feature extraction, training, and evaluation scripts.

## Dataset
A small educational starter dataset of labeled phishing and legitimate URLs, used for learning and prototyping purposes.

## Project Structure
