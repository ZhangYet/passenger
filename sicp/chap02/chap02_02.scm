;; exec 2.26
(define x (list 1 2 3))
(define y (list 4 5 6))
(append x y) ; (1 2 3 4 5 6)
(cons x y)   ; ((1 2 3) 4 5 6)
(list x y)   ; ((1 2 3) (4 5 6))
(car x)      ; 1

;; exec 2.27
(define x (list (list 1 2) (list 3 4)))

(define (deep-reverse x)
  (cond ((null? x) '())
	((not (pair? x)) x)
	(else (append (deep-reverse (cdr x))
		      (list (deep-reverse (car x)))))))

(deep-reverse x)

;; exec 2.28
(define (fringe x)
  (cond ((not (pair? x)) (list x))
	(else (append (fringe (car x))
		      (fringe (cdr x))))))

(fringe x)
