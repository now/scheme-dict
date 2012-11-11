;; TODO: we really need to look through what more can be done at compile-time
;; TODO: batching of commands?
;; TODO: other auth methods?

(define-module (inet dict)
	       :use-module (crypt md5)
	       :use-module (ice-9 optargs)
	       :use-module (ice-9 rdelim)
	       :use-module (ice-9 regex)
	       :use-module (ice-9 syncase)
	       :use-module (srfi srfi-1)
	       :use-module (srfi srfi-13))

(define dict:default-port 2628)
(define dict:default-db "*")
(define dict:default-strategy ".")

(define (dict:read-line sock)
  (let loop ((char (read-char sock))
	     (line (list)))
    (if (and (char=? char #\cr) (char=? (peek-char sock) #\nl))
      (begin
	(read-char sock)
	(list->string (reverse line)))
      (loop (read-char sock) (cons char line)))))

(define (split-line line)
  (let loop ((list (list))
	     (start 0))
    (if (< start (string-length line))
      (let* ((pattern (case (string-ref line start)
			((#\') "'(\\\\.|[^']+)'[ \t]*")
			((#\") "\"(\\\\.|[^\"]+)\"[ \t]*")
			(else  "([^ \t]+)[ \t]*")))
	     (match (string-match pattern line start)))
	(loop (cons (match:substring match 1) list) (match:end match)))
      (reverse list))))

(define (read-response sock)
  (let ((line (dict:read-line sock)))
    (cons (split-line line) line)))

(define-macro (response-params response)
  `(car ,response))

(define-macro (response-line response)
  `(cdr ,response))

(define-macro (response-param response n)
  `(list-ref (response-params ,response) ,n))

(define-macro (response-code response)
  `(string->number (response-param ,response 0)))

(define (read-text sock)
  (let loop ((line (dict:read-line sock))
	     (text (string)))
    (if (string=? line ".")
      text
      (loop (dict:read-line sock)
	  (string-append text
			 (if (and (not (string-null? line))
				  (char=? (string-ref line 0) #\.))
			   (substring line 1)
			   line)
			 "\n")))))

;; this should be a macro of course
(define (send-command sock cmd . args)
  (display (string-append cmd " " (string-join args) "\r\n") sock))

(defmacro* response-error (response #:optional code)
  `(throw 'dict-error
	  (format "Unexpected status code ~A~@[, wanted ~D~]"
		    (response-line ,response)
		    ,code)))

(define-syntax check-response
  (syntax-rules ()
    ((_ response code)
     (or (= code (response-code response))
	 (response-error response code)))))

(define sys-connect connect)
(define* (connect hostname #:optional (port dict:default-port))
  (let* ((host (car (vector-ref (gethost hostname) 4)))
	 (sock (socket AF_INET SOCK_STREAM 0))
	 (igno (sys-connect sock AF_INET host port))
	 (response (read-response sock)))
    (check-response response 220)
    (let* ((n (length (response-params response)))
	   (p2 (response-param response (- n 2)))
	   (caps (string-split (substring p2 1 (1- (string-length p2))) #\.))
	   (msg-id (response-param response (1- n))))
      (values sock caps msg-id))))

(define-macro (command sock command args responses)
  (let ((my-sock (gensym)))
    `(let ((,my-sock ,sock))
       (send-command ,my-sock ,command ,@args)
       (let ((response (read-response ,my-sock))) ;; so we can uses it later
	 (case (response-code response)
	   ,@responses
	   (else (response-error response)))))))

(define (client sock id)
  (command sock "CLIENT" (id) (((250) #t))))

(define-syntax check-read-text
  (syntax-rules ()
    ((_ sock)
     (let ((text (read-text sock)))
       (check-response (read-response sock) 250)
       text))))

(define-macro (read-list sock)
  `(map split-line (drop-right (string-split (check-read-text ,sock) #\nl) 1)))

(define (read-definitions sock)
  (do ((definitions (list) (cons (list (response-param response 2)
				       (response-param response 3)
				       (read-text sock))
				 definitions))
       (response (read-response sock) (read-response sock)))
    ((= (response-code response) 250) (reverse definitions))))

(define* (lookup sock word #:optional (db dict:default-db))
  (command sock "DEFINE" (db word) (((150) (read-definitions sock))
				    ((552) '()))))

(define* (match sock word #:optional (db dict:default-db)
				     (strat dict:default-strategy))
  (command sock "MATCH" (db strat word) (((152) (read-list sock))
					 ((552) '()))))

(define (databases sock)
  (command sock "SHOW DB" () (((110) (read-list sock)) ((554) '()))))

(define (strategies sock)
  (command sock "SHOW STRAT" () (((111) (read-list sock)) ((555) '()))))

(define (info sock db)
  (command sock "SHOW INFO" (db) (((112) (check-read-text sock))
				  ((550) (response-error response 112)))))

(define (server sock)
  (command sock "SHOW SERVER" () (((114) (check-read-text sock)))))

(define (help sock)
  (command sock "HELP" () (((113) (check-read-text sock)))))

(define (can-auth? caps)
  (member "auth" caps))

(define (auth sock user secret msg-id)
  (command sock "AUTH" (user (md5 (string-append msg-id secret)))
	   (((230) #t) ((531) #f))))

(define (dict:quit sock)
  (command sock "QUIT" () (((221) #t))))

(define-macro (disconnect sock)
  `(close-port ,sock))

(export connect client can-auth? auth dict:quit disconnect
	databases strategies info server help
	lookup match
	dict:default-port dict:default-db dict:default-strategy)
