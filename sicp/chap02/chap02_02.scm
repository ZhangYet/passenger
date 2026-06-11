;; exec 2.27
(define x (list (list 1 2) (list 3 4)))

(define (deep-reverse x)
  (cond ((null? x) '())
	((not (pair? x)) x)
	(else (append (deep-reverse (cdr x))
		      (list (deep-reverse (car x)))))))

(deep-reverse x)
