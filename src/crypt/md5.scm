;;; based on work by Jens Axel Søgaard <jensaxel@soegaard.net>

(define-module (crypt md5)
	       :use-module (srfi srfi-1)
	       :use-module (srfi srfi-11)
	       :use-module (util destructure)
	       :export (md5))

(define-macro (mod32 n) `(modulo ,n 4294967296))
(define-macro (word+ w1 w2) `(mod32 (+ ,w1 ,w2)))
(define-macro (word-not w) `(- 4294967295 ,w))
(define-macro (word-or w1 w2) `(logior (mod32 ,w1) (mod32 ,w2)))
(define-macro (word-xor w1 w2) `(logxor (mod32 ,w1) (mod32 ,w2)))
(define-macro (word-and w1 w2) `(logand (mod32 ,w1) (mod32 ,w2)))
(define-macro (word<<< n s)
  `(+ (bit-extract ,n (- 32 ,s) 32) (mod32 (ash ,n ,s))))

;; this could be sped up a bit.
(define (word->bytes word)
  (let ((extract (lambda (w i) (remainder (quotient w (expt 256 i)) 256))))
    (list (extract word 0) (extract word 1) (extract word 2) (extract word 3))))

(define (bytes->word bs)
  (let loop ((acc 0) (mul 1) (bs bs))
    (if (null? bs)
      acc
      (loop (+ acc (* (car bs) mul)) (* 256 mul) (cdr bs)))))

(define (bytes->words bytes)
  (if (null? bytes)
    '()
    (let loop ((bs '()) (bytes bytes))
      (cond
	((null? bytes)	 (list (bytes->word (reverse bs))))
	((< (length bs) 4) (loop (cons (car bytes) bs) (cdr bytes)))
	(else		 (cons (bytes->word (reverse bs)) (loop '() bytes)))))))

;; the MD5 algorithm.  described in RFC 1321 as Step 1-5.
(define (md5 str)
  (let ((b (* 8 (string-length str))))
    (step5 (step4-3 (step2 b (step1 (map char->integer (string->list str))))))))

;; append padding bits
(define (step1 message)
  (let ((padding (modulo (- 448 (* 8 (length message))) 512)))
    (append message (cons #x80 (make-list (quotient (- padding 1) 8) 0)))))

;; append length
(define (step2 b padded)
  (let* ((lo (mod32 b))
         (hi (mod32 (quotient b (expt 2 32)))))
    (bytes->words (append padded (append (word->bytes lo) (word->bytes hi))))))

;; process message in 16bit-word blocks (step3 is implicit in call)
(define (step4-3 message)
  (let loop ((msg message)
	     (A #x67452301) (B #xefcdab89) (C #x98badcfe) (D #x10325476))
    (if (null? msg)
      (list A B C D)
      (let-values (((X rest) (split-at msg 16)))
	(destructure (((AA BB CC DD)
		       (apply round4
			     (apply round3
				   (apply round2
					 (round1 A B C D (list->vector X)))))))
	  (apply loop rest (map + (list A B C D) (list AA BB CC DD))))))))

;; gates for round functions
(define (F x y z) (word-or (word-and x y) (word-and (word-not x) z)))
(define (G x y z) (word-or (word-and x z) (word-and y (word-not z))))
(define (H x y z) (word-xor x (word-xor y z)))
(define (I x y z) (word-xor y (word-or x (word-not z))))

;; sine table for round functions
(define T
  (let* ((t (lambda (i) (inexact->exact (floor (* 4294967296 (abs (sin i)))))))
         (v (list->vector (map t (iota 64 1)))))
    (lambda (i) (vector-ref v (- i 1)))))

;; symbols are substituted with indices, e.g. 'DABC |-> (list 3 0 1 2)
(define (prepare ops)
  (define (symbol->indices s)
    (list->vector (map (lambda (n) (- (char->integer n) (char->integer #\A)))
		       (string->list (symbol->string s)))))
  (map (lambda (l) (cons (symbol->indices (car l)) (cdr l))) ops))

;; the operations for each round
(define round1-operations
  (prepare
   '((ABCD  0  7  1)  (DABC  1 12  2)  (CDAB  2 17  3)  (BCDA  3 22  4)
     (ABCD  4  7  5)  (DABC  5 12  6)  (CDAB  6 17  7)  (BCDA  7 22  8)
     (ABCD  8  7  9)  (DABC  9 12 10)  (CDAB 10 17 11)  (BCDA 11 22 12)
     (ABCD 12  7 13)  (DABC 13 12 14)  (CDAB 14 17 15)  (BCDA 15 22 16))))
(define round2-operations
  (prepare
   '((ABCD  1  5 17)  (DABC  6  9 18)  (CDAB 11 14 19)  (BCDA  0 20 20)
     (ABCD  5  5 21)  (DABC 10  9 22)  (CDAB 15 14 23)  (BCDA  4 20 24)
     (ABCD  9  5 25)  (DABC 14  9 26)  (CDAB  3 14 27)  (BCDA  8 20 28)
     (ABCD 13  5 29)  (DABC  2  9 30)  (CDAB  7 14 31)  (BCDA 12 20 32))))
(define round3-operations
  (prepare
   '((ABCD  5  4 33)  (DABC  8 11 34)  (CDAB 11 16 35)  (BCDA 14 23 36)
     (ABCD  1  4 37)  (DABC  4 11 38)  (CDAB  7 16 39)  (BCDA 10 23 40)
     (ABCD 13  4 41)  (DABC  0 11 42)  (CDAB  3 16 43)  (BCDA  6 23 44)
     (ABCD  9  4 45)  (DABC 12 11 46)  (CDAB 15 16 47)  (BCDA  2 23 48))))
(define round4-operations
  (prepare
   '((ABCD  0  6 49)  (DABC  7 10 50)  (CDAB 14 15 51)  (BCDA  5 21 52)
     (ABCD 12  6 53)  (DABC  3 10 54)  (CDAB 10 15 55)  (BCDA  1 21 56)
     (ABCD  8  6 57)  (DABC 15 10 58)  (CDAB  6 15 59)  (BCDA 13 21 60)
     (ABCD  4  6 61)  (DABC 11 10 62)  (CDAB  2 15 63)  (BCDA  9 21 64))))

;; round functions
(define-macro (round-function f)
  `(lambda (a b c d X k i s)
     (word+ b (word<<< (word+ a (word+ (,f b c d) (word+ (vector-ref X k)
							 (T i))))
		       s))))

(define rf1 (round-function F))
(define rf2 (round-function G))
(define rf3 (round-function H))
(define rf4 (round-function I))

;; execute the rounds operations using the rf[1-4] functions and permutations.
(define (round a b c d X rf ops)
  (let loop ((a a) (b b) (c c) (d d) (X X) (rf rf) (ops ops))
    (if (null? ops)
        (list a b c d X)
	(destructure (((#(i0 i1 i2 i3) k s i) (car ops)))
	  (let* ((v (vector a b c d))
		 (a (vector-ref v i0))
		 (b (vector-ref v i1))
		 (c (vector-ref v i2))
		 (d (vector-ref v i3))
		 (a (rf a b c d X k i s)))
	    (vector-set! v i0 a)
	    (destructure ((#(a b c d) v))
	      (loop a b c d X rf (cdr ops))))))))

;; helper functions (to apply's above)
(define (round1 a b c d X) (round a b c d X rf1 round1-operations))
(define (round2 a b c d X) (round a b c d X rf2 round2-operations))
(define (round3 a b c d X) (round a b c d X rf3 round3-operations))
(define (round4 a b c d X) (round a b c d X rf4 round4-operations))

;; output - could be simpler perhaps
(define (step5 l)
  (let ((number->hex (lambda (n)
		       (let ((str (number->string n 16)))
			 (if (< n 16) (string-append "0" str) str)))))
    (apply string-append (map number->hex (append-map word->bytes l)))))
