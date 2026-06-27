;; exec 3.12
(define x (list 'a 'b))
(define y (list 'c 'd))
(define z (append x y))
z
(cdr x)
(define w (append! x y))
w
(cdr x)

;; exec 3.13
(define (last-pair x)
  (if (null? (cdr x))
      x
      (last-pair (cdr x))))

(define (make-cycle x)
  (set-cdr! (last-pair x) x)
  x)

(define z (make-cycle (list 'a 'b 'c)))
;; WARNING: (last-pair z) infinite loop
