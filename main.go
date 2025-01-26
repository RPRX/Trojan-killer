package main

import (
    "bufio"
    "bytes"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "sync"
    "time"
)

// CCS pattern for TLS Change Cipher Spec
var CCS = []byte{20, 3, 3, 0, 1, 1}

type trojanStream struct {
    first    bool
    count    bool
    rev      bool
    seq      [4]int
    seqIndex int
}

func newTrojanStream() *trojanStream {
    return &trojanStream{first: true}
}

func main() {
    fmt.Printf("Trojan-killer v2.0.0 started\n")
    l, err := net.Listen("tcp4", "127.0.0.1:12345")
    if err != nil {
        fmt.Printf("Failed to listen: %v\n", err)
        return
    }
    fmt.Printf("Listening on %v\n\n", l.Addr())
    
    for {
        c, err := l.Accept()
        if err != nil {
            continue
        }
        go Handle(c)
    }
}

func Handle(c net.Conn) {
    req, err := http.ReadRequest(bufio.NewReader(c))
    if err != nil {
        return
    }
    
    state := "accepted"
    if !strings.EqualFold(req.Method, "CONNECT") {
        state = "rejected"
    }
    fmt.Printf("%v from %v %v %v\n", time.Now().Format(time.DateTime), c.RemoteAddr(), state, req.URL.Host)
    if state == "rejected" {
        return
    }

    conn, err := net.Dial("tcp", req.URL.Host)
    if err != nil {
        return
    }
    defer conn.Close()
    
    c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

    var mutex sync.Mutex
    stream := newTrojanStream()

    go func() {
        buf := make([]byte, 8192)
        for {
            n, err := c.Read(buf)
            if err != nil {
                return
            }
            
            mutex.Lock()
            processed := processData(stream, false, buf[:n])
            mutex.Unlock()

            if processed && stream.seqIndex == 4 {
                if isTrojanSeq(stream.seq) {
                    fmt.Printf("%v is Trojan (Decision Tree)\n", req.URL.Host)
                }
                return
            }

            _, err = conn.Write(buf[:n])
            if err != nil {
                return
            }
        }
    }()

    go func() {
        buf := make([]byte, 8192)
        for {
            n, err := conn.Read(buf)
            if err != nil {
                return
            }

            mutex.Lock()
            processed := processData(stream, true, buf[:n])
            mutex.Unlock()

            if processed && stream.seqIndex == 4 {
                if isTrojanSeq(stream.seq) {
                    fmt.Printf("%v is Trojan (Decision Tree)\n", req.URL.Host)
                }
                return
            }

            _, err = c.Write(buf[:n])
            if err != nil {
                return
            }
        }
    }()
}

func processData(s *trojanStream, rev bool, data []byte) bool {
    if len(data) == 0 {
        return false
    }

    if s.first {
        s.first = false
        // Stop if it's not a valid TLS connection
        if !(!rev && len(data) >= 3 && data[0] >= 0x16 && data[0] <= 0x17 &&
            data[1] == 0x03 && data[2] <= 0x09) {
            return true
        }
    }

    if !rev && !s.count && len(data) >= 6 && bytes.Equal(data[:6], CCS) {
        // Client Change Cipher Spec encountered, start counting
        s.count = true
    }

    if s.count {
        if rev == s.rev {
            // Same direction as last time, just update the number
            s.seq[s.seqIndex] += len(data)
        } else {
            // Different direction, bump the index
            s.seqIndex++
            if s.seqIndex == 4 {
                return true
            }
            s.seq[s.seqIndex] += len(data)
            s.rev = rev
        }
    }

    return false
}

// isTrojanSeq implements the decision tree classifier
func isTrojanSeq(seq [4]int) bool {
	length1 := seq[0]
	length2 := seq[1]
	length3 := seq[2]
	length4 := seq[3]

	if length2 <= 2431 {
		if length2 <= 157 {
			if length1 <= 156 {
				if length3 <= 108 {
					return false
				} else {
					return false
				}
			} else {
				if length1 <= 892 {
					if length3 <= 40 {
						return false
					} else {
						if length3 <= 788 {
							if length4 <= 185 {
								if length1 <= 411 {
									return true
								} else {
									return false
								}
							} else {
								if length2 <= 112 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length3 <= 1346 {
								if length1 <= 418 {
									return false
								} else {
									return true
								}
							} else {
								return false
							}
						}
					}
				} else {
					if length2 <= 120 {
						if length2 <= 63 {
							return false
						} else {
							if length4 <= 653 {
								return false
							} else {
								return false
							}
						}
					} else {
						return false
					}
				}
			}
		} else {
			if length1 <= 206 {
				if length1 <= 185 {
					if length1 <= 171 {
						return false
					} else {
						if length4 <= 211 {
							return false
						} else {
							return false
						}
					}
				} else {
					if length2 <= 251 {
						return true
					} else {
						return false
					}
				}
			} else {
				if length2 <= 286 {
					if length1 <= 1123 {
						if length3 <= 70 {
							return false
						} else {
							if length1 <= 659 {
								if length3 <= 370 {
									return true
								} else {
									return false
								}
							} else {
								if length4 <= 272 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						if length4 <= 537 {
							if length2 <= 276 {
								if length3 <= 1877 {
									return false
								} else {
									return false
								}
							} else {
								return false
							}
						} else {
							if length1 <= 1466 {
								if length1 <= 1435 {
									return false
								} else {
									return true
								}
							} else {
								if length2 <= 193 {
									return false
								} else {
									return false
								}
							}
						}
					}
				} else {
					if length1 <= 284 {
						if length1 <= 277 {
							if length2 <= 726 {
								return false
							} else {
								if length2 <= 768 {
									return true
								} else {
									return false
								}
							}
						} else {
							if length2 <= 782 {
								if length4 <= 783 {
									return true
								} else {
									return false
								}
							} else {
								return false
							}
						}
					} else {
						if length2 <= 492 {
							if length2 <= 396 {
								if length2 <= 322 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 971 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length2 <= 2128 {
								if length2 <= 1418 {
									return false
								} else {
									return false
								}
							} else {
								if length3 <= 103 {
									return false
								} else {
									return false
								}
							}
						}
					}
				}
			}
		}
	} else {
		if length2 <= 6232 {
			if length3 <= 85 {
				if length2 <= 3599 {
					return false
				} else {
					if length1 <= 613 {
						return false
					} else {
						return false
					}
				}
			} else {
				if length3 <= 220 {
					if length4 <= 1173 {
						if length1 <= 874 {
							if length4 <= 337 {
								if length4 <= 68 {
									return true
								} else {
									return true
								}
							} else {
								if length1 <= 667 {
									return true
								} else {
									return true
								}
							}
						} else {
							if length3 <= 108 {
								if length1 <= 1930 {
									return true
								} else {
									return true
								}
							} else {
								if length2 <= 5383 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						return false
					}
				} else {
					if length1 <= 664 {
						if length3 <= 411 {
							if length3 <= 383 {
								if length4 <= 346 {
									return true
								} else {
									return false
								}
							} else {
								if length1 <= 445 {
									return true
								} else {
									return false
								}
							}
						} else {
							if length2 <= 3708 {
								if length4 <= 307 {
									return true
								} else {
									return false
								}
							} else {
								if length2 <= 4656 {
									return false
								} else {
									return false
								}
							}
						}
					} else {
						if length1 <= 1055 {
							if length3 <= 580 {
								if length1 <= 724 {
									return true
								} else {
									return false
								}
							} else {
								if length1 <= 678 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length2 <= 5352 {
								if length3 <= 1586 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 2173 {
									return true
								} else {
									return false
								}
							}
						}
					}
				}
			}
		} else {
			if length2 <= 9408 {
				if length1 <= 670 {
					if length4 <= 76 {
						if length3 <= 175 {
							return true
						} else {
							return true
						}
					} else {
						if length2 <= 9072 {
							if length3 <= 314 {
								if length3 <= 179 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 708 {
									return false
								} else {
									return false
								}
							}
						} else {
							return true
						}
					}
				} else {
					if length1 <= 795 {
						if length2 <= 6334 {
							if length2 <= 6288 {
								return true
							} else {
								return false
							}
						} else {
							if length4 <= 6404 {
								if length2 <= 8194 {
									return true
								} else {
									return true
								}
							} else {
								if length2 <= 8924 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						if length3 <= 732 {
							if length1 <= 1397 {
								if length3 <= 179 {
									return false
								} else {
									return false
								}
							} else {
								if length1 <= 1976 {
									return false
								} else {
									return false
								}
							}
						} else {
							if length1 <= 2840 {
								if length1 <= 2591 {
									return false
								} else {
									return true
								}
							} else {
								return false
							}
						}
					}
				}
			} else {
				if length4 <= 30 {
					return false
				} else {
					if length2 <= 13314 {
						if length4 <= 1786 {
							if length2 <= 13018 {
								if length4 <= 869 {
									return false
								} else {
									return false
								}
							} else {
								return true
							}
						} else {
							if length3 <= 775 {
								return false
							} else {
								return false
							}
						}
					} else {
						if length4 <= 73 {
							return false
						} else {
							if length3 <= 640 {
								if length3 <= 237 {
									return false
								} else {
									return false
								}
							} else {
								if length2 <= 43804 {
									return false
								} else {
									return false
								}
							}
						}
					}
				}
			}
		}
	}
}
