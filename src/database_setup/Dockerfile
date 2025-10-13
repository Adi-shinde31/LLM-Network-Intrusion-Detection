# ---------------------------
# Dockerfile for Jupyter Notebook Runner
# ---------------------------

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Jupyter + nbconvert (for running .ipynb files)
RUN pip install jupyter nbconvert

# Copy the notebook
COPY load_to_postgre.ipynb .

# Command to execute the notebook as a script
CMD ["jupyter", "nbconvert", "--to", "script", "--execute", "--inplace", "load_to_postgre.ipynb"]
