;; exec 3.1
(define (make-accumulator base)
  (lambda (amount)
    (begin (set! base (+ base amount)))
    base))

(define A1 (make-accumulator 10))
(define A2 (make-accumulator 2))
