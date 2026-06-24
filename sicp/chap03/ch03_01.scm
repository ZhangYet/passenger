;; exec 3.1
(define (make-accumulator base)
  (lambda (amount)
    (begin (set! base (+ base amount)))
    base))

(define A1 (make-accumulator 10))
(define A2 (make-accumulator 2))

;; exec 3.2
;; 参考答案和这个答案一样，处理不了多个参数的函数
(define (make-monitor func)
  (let ((count 0))
    (define (dispatch m)
      (cond ((eq? m 'how-many-times) count)
	    ((eq? m 'reset-count) (begin (set! count 0)
					 count))
	    (else (begin (set! count (+ count 1))
			 (func m)))))
    dispatch))

;;
