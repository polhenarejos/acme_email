# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 19:25:29 2021

@author: Pol
"""

class Error(Exception):
    def __init__(self, message):
        super().__init__(message)

class FromAddressMismatch(Error):
    def __init__(self):
        super().__init__('Email From Address does not match with challenge From Address')

class ReceiptAddressMismatch(Error):
    def __init__(self):
        super().__init__('Email Receipt Address does not match with challenge email identifier')

