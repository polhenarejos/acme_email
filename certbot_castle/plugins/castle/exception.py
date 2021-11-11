# -*- coding: utf-8 -*-
"""
Created on Thu Nov 11 19:25:29 2021

@author: Pol
"""

class Error(Exception):
    def __init__(self, message):
        super().__init__(message)

