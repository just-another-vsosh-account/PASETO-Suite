# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import ITab
from burp import IMessageEditorController
from burp import IMessageEditor
from burp import IParameter
from burp import IHttpRequestResponse
from burp import IHttpService
from javax import swing
from java.awt import BorderLayout
import json
import base64
import os
import time
import sys

# Добавляем путь к текущей директории в sys.path
current_dir = os.getcwd()
if current_dir not in sys.path:
    sys.path.append(current_dir)

import lib

class BurpExtender(IBurpExtender, ITab, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Настройка расширения
        callbacks.setExtensionName("PASETO Editor")
        
        # Инициализация PASETO
        self._paseto = lib.Paseto()
        
        # Создание UI
        self._createUI()
        
        # Регистрация таба
        callbacks.addSuiteTab(self)
        
        # Регистрация обработчика HTTP сообщений
        callbacks.registerHttpListener(self)
        
    def _createUI(self):
        self._panel = swing.JPanel(BorderLayout())
        
        # Создание редактора сообщений
        self._messageEditor = self._callbacks.createMessageEditor(self, False)
        
        # Создание панели с кнопками
        buttonPanel = swing.JPanel()
        
        # Кнопка для декодирования токена
        decodeButton = swing.JButton("Decode PASETO")
        decodeButton.actionPerformed = self._decodePaseto
        buttonPanel.add(decodeButton)
        
        # Кнопка для подписания токена
        signButton = swing.JButton("Sign PASETO")
        signButton.actionPerformed = self._signPaseto
        buttonPanel.add(signButton)
        
        # Кнопка для загрузки ключа
        loadKeyButton = swing.JButton("Load Key")
        loadKeyButton.actionPerformed = self._loadKey
        buttonPanel.add(loadKeyButton)
        
        # Кнопка для генерации ключа
        generateKeyButton = swing.JButton("Generate Key")
        generateKeyButton.actionPerformed = self._generateKey
        buttonPanel.add(generateKeyButton)
        
        # Кнопка для атаки на none algorithm
        noneAttackButton = swing.JButton("None Algorithm Attack")
        noneAttackButton.actionPerformed = self._noneAlgorithmAttack
        buttonPanel.add(noneAttackButton)
        
        # Кнопка для атаки на weak key
        weakKeyAttackButton = swing.JButton("Weak Key Attack")
        weakKeyAttackButton.actionPerformed = self._weakKeyAttack
        buttonPanel.add(weakKeyAttackButton)
        
        # Кнопка для атаки на key confusion
        keyConfusionAttackButton = swing.JButton("Key Confusion Attack")
        keyConfusionAttackButton.actionPerformed = self._keyConfusionAttack
        buttonPanel.add(keyConfusionAttackButton)
        
        # Добавление компонентов на панель
        self._panel.add(buttonPanel, BorderLayout.NORTH)
        self._panel.add(self._messageEditor.getComponent(), BorderLayout.CENTER)
        
        # Инициализация переменных для ключей
        self._private_key = None
        self._public_key = None
        
    def getTabCaption(self):
        return "PASETO Editor"
        
    def getUiComponent(self):
        return self._panel
        
    def _decodePaseto(self, event):
        message = self._messageEditor.getMessage()
        if message:
            try:
                token = message.decode('utf-8')
                decoded = self._paseto.decode(token)
                self._messageEditor.setMessage(json.dumps(decoded, indent=2).encode('utf-8'))
            except Exception as e:
                swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
                
    def _signPaseto(self, event):
        if not self._private_key:
            swing.JOptionPane.showMessageDialog(self._panel, "Please load or generate a key first", "Error", swing.JOptionPane.ERROR_MESSAGE)
            return
            
        message = self._messageEditor.getMessage()
        if message:
            try:
                payload = json.loads(message.decode('utf-8'))
                token = self._paseto.sign(payload, self._private_key)
                self._messageEditor.setMessage(token.encode('utf-8'))
            except Exception as e:
                swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
                
    def _loadKey(self, event):
        fileChooser = swing.JFileChooser()
        if fileChooser.showOpenDialog(self._panel) == swing.JFileChooser.APPROVE_OPTION:
            try:
                with open(fileChooser.getSelectedFile().getPath(), 'rb') as f:
                    key_data = f.read()
                    self._private_key = key_data
                    swing.JOptionPane.showMessageDialog(self._panel, "Key loaded successfully", "Success", swing.JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
                
    def _generateKey(self, event):
        try:
            self._private_key, self._public_key = self._paseto.generate_key()
            # Сохранение ключей в файлы
            with open('private_key.pem', 'wb') as f:
                f.write(self._private_key)
            with open('public_key.pem', 'wb') as f:
                f.write(self._public_key)
            swing.JOptionPane.showMessageDialog(self._panel, "Keys generated and saved successfully", "Success", swing.JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
            
    def _noneAlgorithmAttack(self, event):
        message = self._messageEditor.getMessage()
        if message:
            try:
                payload = json.loads(message.decode('utf-8'))
                # Создание токена с алгоритмом none
                token = self._paseto.create_none_token(payload)
                self._messageEditor.setMessage(token.encode('utf-8'))
            except Exception as e:
                swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
                
    def _weakKeyAttack(self, event):
        try:
            # Генерация слабого ключа
            weak_key = self._paseto.generate_weak_key()
            # Сохранение слабого ключа
            with open('weak_key.pem', 'wb') as f:
                f.write(weak_key)
            self._private_key = weak_key
            swing.JOptionPane.showMessageDialog(self._panel, "Weak key generated and loaded", "Success", swing.JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
            
    def _keyConfusionAttack(self, event):
        if not self._public_key:
            swing.JOptionPane.showMessageDialog(self._panel, "Please load a public key first", "Error", swing.JOptionPane.ERROR_MESSAGE)
            return
            
        message = self._messageEditor.getMessage()
        if message:
            try:
                payload = json.loads(message.decode('utf-8'))
                # Использование публичного ключа как приватного
                token = self._paseto.sign(payload, self._public_key)
                self._messageEditor.setMessage(token.encode('utf-8'))
            except Exception as e:
                swing.JOptionPane.showMessageDialog(self._panel, str(e), "Error", swing.JOptionPane.ERROR_MESSAGE)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzedResponse = self._helpers.analyzeResponse(response)
            headers = analyzedResponse.getHeaders()
            
            for header in headers:
                if "Authorization" in header and "Bearer" in header:
                    token = header.split("Bearer ")[1]
                    if self._isPasetoToken(token):
                        self._messageEditor.setMessage(token.encode('utf-8'))
                        
    def _isPasetoToken(self, token):
        try:
            version = token.split('.')[0]
            return version in ['v1', 'v2', 'v3', 'v4']
        except:
            return False