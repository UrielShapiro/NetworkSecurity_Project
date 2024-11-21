FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Install Python and TCP Replay
RUN powershell -Command \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.12.0/python-3.12.0.exe -OutFile python-installer.exe; \
    Start-Process python-installer.exe -ArgumentList '/quiet', 'InstallAllUsers=1', 'PrependPath=1' -NoNewWindow -Wait; \
    Remove-Item -Force python-installer.exe

# Install TCP Replay (if necessary, or use an alternative method for Windows)
RUN powershell -Command \
    Invoke-WebRequest -Uri https://github.com/alonbl/tcpreplay/releases/download/v4.4.0/tcpreplay-4.4.0-win64.zip -OutFile tcpreplay.zip; \
    Expand-Archive tcpreplay.zip -DestinationPath C:\tcpreplay; \
    Remove-Item -Force tcpreplay.zip

# Set up the working directory and copy your application
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN python -m pip install --upgrade pip
RUN pip install -r requirements.txt

# Run your program
CMD ["python", "your_program.py"]
