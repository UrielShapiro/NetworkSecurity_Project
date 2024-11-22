# Use an Ubuntu base image
FROM ubuntu:22.04

# Set non-interactive mode for APT to avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libffi-dev \
    libssl-dev \
    net-tools \
    iproute2 \
    tcpreplay \
    pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set up the working directory
WORKDIR /app

# Copy your application files to the container
COPY . /app

# Install Python dependencies from requirements.txt
RUN pip3 install -r requirements.txt

# Set the default command to run your Python program
CMD ["/bin/bash"]
