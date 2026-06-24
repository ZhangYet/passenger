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

;; exec 3.3
(define (make-account balance secret)
  (define (withdraw amount)
    (if (>= balance amount)
	(begin (set! balance (- balance amount))
	       balance)
	"Insufficent funds"))
  (define (deposit amount)
    (set! balance (+ balance amount))
    balance)
  (define (dispatch sec m)
    (if (not (eq? sec secret))
	(error "Wrong secret -- MAKE-ACCOUNT" sec)
	(cond ((eq? m 'withdraw) withdraw)
	       ((eq? m 'deposit) deposit)
	       (else "Unknown request -- MAKE-ACCOUNT" m))))
  dispatch)


(define acc (make-account 1000 'dasfweace))

((acc 'dasfwece 'deposit) 10)

;; exec 3.4
(define (make-account balance secret)
  (let ((thres 3))
    (define (withdraw amount)
      (if (>= balance amount)
	  (begin (set! balance (- balance amount))
		 balance)
	  "Insufficent funds"))
    (define (deposit amount)
      (set! balance (+ balance amount))
      balance)
    (define (dispatch sec m)
      (if (not (eq? sec secret))
	  (begin (set! thres (- thres 1))
		 (if (= thres 0)
		     (error "CALL THE POLICE!!!!!"))
		 (error "Wrong secret -- MAKE-ACCOUNT" sec))
	  (begin
	    (cond ((eq? m 'withdraw) withdraw)
		  ((eq? m 'deposit) deposit)
		  (else "Unknown request -- MAKE-ACCOUNT" m))
	    (set! thres 3))))
    dispatch))

(define acc (make-account 100 'password))
