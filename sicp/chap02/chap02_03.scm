(define (memq item x)
  (cond ((null? x) #f)
	((eq? item (car x)) x)
	(else (memq item (cdr x)))))

;; exec 2.53
(list 'a 'b 'c)               ;; (a b c) 没有引号
(list (list 'george))         ;; ((george)) 也没有引号
(cdr '((x1 x2) (y1 y2)))      ;; ((y1 y2))
(cadr '((x1 x2) (y1 y2)))     ;; (y1 y2)
(pair? (car '(a short list))) ;; #f

(memq 'red '((red shoe) (blue socks))) ;; #f
(memq 'red '(red shoe blud sockes))    ;; (red shoe blud socks)

;; exec 2.54
(define (equal? x y)
  (if (and (pair? x) (pair? y))
      (and (equal? (car x) (car y))
	   (equal? (cdr x) (cdr y)))
      (eq? x y)))

(equal? '(this is a list) '(this is a list))
(equal? '(this is a list) '(this (is a) list))

(equal? 'a 'a)
(equal? 'a '(a))

;; exec 2.55
;; 因为 ''xzdadfa 的结果就是 (quote xzdadfa) 再对它取 car 就是 quota

;; sec 2.3.2
(define (=number? x y)
  (and (number? x) (= x y)))

(define (variable? x) (symbol? x))
(define (same-variable? v1 v2)
  (and (variable? v1) (variable? v2) (eq? v1 v2)))

(define (make-sum a1 a2)
  (cond ((=number? a1 0) a2)
	((=number? a2 0) a1)
	((and (number? a1) (number? a2)) (+ a1 a2))
	(else (list '+ a1 a2))))
(define (sum? x)
  (and (pair? x) (eq? (car x) '+)))
(define (addend s) (cadr s))
(define (augend s) (caddr s))

(define (make-product m1 m2)
  (cond ((or (=number? m1 0) (=number? m2 0)) 0)
	((=number? m1 1) m2)
	((=number? m2 1) m1)
	((and (number? m1) (number? m2)) (* m1 m2))
	(else (list '* m1 m2))))
(define (product? x)
  (and (pair? x) (eq? (car x) '*)))
(define (multiplier p) (cadr p))
(define (multiplicand p) (caddr p))

(define (deriv exp var)
  (cond ((number? exp) 0)
	((variable? exp)
	 (if (same-variable? exp var) 1 0))
	((sum? exp)
	 (make-sum (deriv (addend exp) var)
		   (deriv (augend exp) var)))
	((product? exp)
	 (make-sum
	  (make-product (multiplier exp)
			(deriv (multiplicand exp) var))
	  (make-product (deriv (multiplier exp) var)
			(multiplicand exp))))
	(else (error "unknown expression type -- DERIV" exp))))

(deriv '(+ x 1) 'x)
(deriv '(* x y) 'x)
(deriv '(* (* x y) (+ x 3)) 'x)

;; exec 2.56
(define (exponentiation? x)
  (eq? (car x) '**))
(define (base x) (cadr x))
(define (exponent x) (caddr x))
(define (make-exponentiation b ex)
  (cond ((= ex 0) 1)
	((= ex 1) b)
	(else (list '** b ex))))

(define (deriv exp var)
  (cond ((number? exp) 0)
	((variable? exp)
	 (if (same-variable? exp var) 1 0))
	((sum? exp)
	 (make-sum (deriv (addend exp) var)
		   (deriv (augend exp) var)))
	((product? exp)
	 (make-sum
	  (make-product (multiplier exp)
			(deriv (multiplicand exp) var))
	  (make-product (deriv (multiplier exp) var)
			(multiplicand exp))))
	((exponentiation? exp)
	 (make-product (exponent exp)
		       (make-product (make-exponentiation (base exp) (- (exponent exp) 1))
				     (deriv (base exp) var))))
	(else (error "unknown expression type -- DERIV" exp))))
