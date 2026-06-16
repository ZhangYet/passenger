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
(define (sum? expr)
  (and (pair? expr) (eq? (car expr) '+)))
(define (addend expr) (cadr expr))
(define (augend expr) (caddr expr))

(define (make-product m1 m2)
  (cond ((or (=number? m1 0) (=number? m2 0)) 0)
	((=number? m1 1) m2)
	((=number? m2 1) m1)
	((and (number? m1) (number? m2)) (* m1 m2))
	(else (list '* m1 m2))))
(define (product? expr)
  (and (pair? expr) (eq? (car expr) '*)))
(define (multiplier expr) (cadr expr))
(define (multiplicand expr) (caddr expr))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	(else (error "unknown expression type -- DERIV" expr))))

(deriv '(+ x 1) 'x)
(deriv '(* x y) 'x)
(deriv '(* (* x y) (+ x 3)) 'x)

;; exec 2.56
(define (exponentiation? expr)
  (eq? (car expr) '**))
(define (base expr) (cadr expr))
(define (exponent expr) (caddr expr))
(define (make-exponentiation b ex)
  (cond ((= ex 0) 1)
	((= ex 1) b)
	(else (list '** b ex))))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	((exponentiation? expr)
	 (make-product (exponent expr)
		       (make-product (make-exponentiation (base expr) (- (exponent expr) 1))
				     (deriv (base expr) var))))
	(else (error "unknown expression type -- DERIV" expr))))

;; exec 2.57
(define (augend expr)
  (if (= (length (cddr expr)) 1)
      (caddr expr)
      (cons '+ (cddr expr))))

(define (multiplicand expr)
  (if (= (length (cddr expr)) 1)
      (caddr expr)
      (cons '* (cddr expr))))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	((exponentiation? expr)
	 (make-product (exponent expr)
		       (make-product (make-exponentiation (base expr) (- (exponent expr) 1))
				     (deriv (base expr) var))))
	(else (error "unknown expression type -- DERIV" expr))))

(deriv '(* x y (+ x 3)) 'x)
(deriv '(* 1 2 3 4 5 x) 'x)

;; exec 2.58
(define (sum? expr)
  (and (pair? expr) (eq? (cadr expr) '+)))

(define (addend expr) (car expr))
(define (augend expr)
  (if (null? (cdddr expr))
      (caddr expr)
      (cddr expr)))

(define (make-sum a1 a2)
  (cond ((=number? a2 0) a1)
	((=number? a1 0) a2)
	((and (number? a1) (number? a2)) (+ a1 a2))
	(else (list a1 '+ a2))))

(define (product? expr)
  (and (pair? expr) (eq? (cadr expr) '*)))

(define (multiplier expr) (car expr))
(define (multiplicand expr)
  (if (null? (cdddr expr))
      (caddr expr)
      (cddr expr)))

(define (make-product m1 m2)
  (cond ((or (=number? m1 0) (=number? m2 0)) 0)
	((=number? m1 1) m2)
	((=number? m2 1) m1)
	((and (number? m1) (number? m2)) (* m1 m2))
	(else (list m1 '* m2))))

(define (deriv expr var)
  (cond ((number? expr) 0)
	((variable? expr)
	 (if (same-variable? expr var) 1 0))
	((sum? expr)
	 (make-sum (deriv (addend expr) var)
		   (deriv (augend expr) var)))
	((product? expr)
	 (make-sum
	  (make-product (multiplier expr)
			(deriv (multiplicand expr) var))
	  (make-product (deriv (multiplier expr) var)
			(multiplicand expr))))
	(else (error "unknown expression type -- DERIV" expr))))

(define sample '(x * (x * y)))

;; sec 2.3.3
(define (element-of-set? x set)
  (cond ((null? set) #f)
	((equal? x (car set)) #t)
	(else (element-of-set? x (cdr set)))))

(define (adjoin-set x set)
  (if (element-of-set? x set)
      set
      (cons x set)))

(define (intersection-set set1 set2)
  (cond ((or (null? set1) (null? set2)) '())
	((element-of-set? (car set1) set2)
	 (cons (car set1) (intersection-set (cdr set1) set2)))
	(else (intersection-set (cdr set1) set2))))

;; exec 2.59
(define (union-set set1 set2)
  (cond ((null? set1) set2)
	((element-of-set? (car set1) set2)
	 (union-set (cdr set1) set2))
	(else (cons (car set1) (union-set (cdr set1) set2)))))
