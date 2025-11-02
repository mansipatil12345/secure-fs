#!/bin/bash
# SecureFS Installation Script

echo "🔒 SecureFS Installation Script"
echo "================================"

# Check Python version
echo "📋 Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if we're on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Detected macOS"
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew is required but not installed"
        echo "   Install from: https://brew.sh/"
        exit 1
    fi
    
    # Install macFUSE
    echo "📦 Installing macFUSE..."
    brew install --cask macfuse
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Detected Linux"
    
    # Install FUSE for Linux
    echo "📦 Installing FUSE..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y fuse libfuse-dev
    elif command -v yum &> /dev/null; then
        sudo yum install -y fuse fuse-devel
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y fuse fuse-devel
    else
        echo "❌ Unsupported Linux distribution"
        echo "   Please install FUSE manually"
        exit 1
    fi
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Failed to install Python dependencies"
    exit 1
fi

# Setup repository
echo "🔧 Setting up repository..."
python3 setup_repo.py
if [ $? -ne 0 ]; then
    echo "❌ Failed to setup repository"
    exit 1
fi

# Run quick test
echo "🧪 Running quick component test..."
python3 setup_repo.py --test

echo ""
echo "✅ SecureFS installation complete!"
echo ""
echo "🚀 Quick Start:"
echo "   mkdir -p ~/secure_storage ~/secure_mount"
echo "   python3 src/secure_fs.py ~/secure_storage ~/secure_mount"
echo ""
echo "📖 For detailed testing instructions, see HOW_TO_TEST.md"
