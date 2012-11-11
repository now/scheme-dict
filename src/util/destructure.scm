;;; Based on work by Richard Kelsey and Jonathan Rees.

(define-module (util destructure)
               :use-module (ice-9 syncase)
               :export-syntax (destructure))

;; cons:ing instead of append:ing now.  does it work for everything?
(define-macro (destructure specs . body)
  (let ((atom? (lambda (x) (not (pair? x)))))
    (letrec ((expand-pattern
               (lambda (pattern value)
                 (cond
                   ((or (not pattern) (null? pattern)) '())
                   ((vector? pattern)
                    (let ((xvalue (if (atom? value) value (gensym))))
                      `(,@(if (eq? value xvalue) '() `((,xvalue ,value)))
                         ,@(expand-vector pattern xvalue))))
                   ((atom? pattern) `((,pattern ,value)))
                   (else
                     (let ((xvalue (if (atom? value) value (gensym))))
                       `(,@(if (eq? value xvalue) '() `((,xvalue ,value)))
                          ,@(expand-pattern (car pattern) `(car ,xvalue))
                          ,@(if (null? (cdr pattern))
                              '()
                              (expand-pattern (cdr pattern)
                                              `(cdr ,xvalue)))))))))
             (expand-vector
               (lambda (vec xvalue)
                 (do ((j (- (vector-length vec) 1) (- j 1))
                      (ps '() (cons (car (expand-pattern (vector-ref vec j)
                                                    `(vector-ref ,xvalue ,j)))
                                    ps)))
                   ((< j 0) ps)))))
      (do ((specs specs (cdr specs))
           (res '() (cons (expand-pattern (caar specs) (cadar specs)) res)))
        ((null? specs) `(let* ,(car (reverse res)) . ,body))))))
