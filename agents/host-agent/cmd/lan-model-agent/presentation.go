package main

import "regexp"

var operatorCodePattern = regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$`)
